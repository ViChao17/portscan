package portscan

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"
)

const (
	defaultConcurrency    = 100
	defaultConnectTimeout = time.Second
)

// Result describes the outcome of a single TCP connect attempt.
type Result struct {
	// Host is the host exactly as it was supplied by the caller, with
	// surrounding whitespace removed. For an IP literal it is the literal.
	Host string

	// IP is the address that was actually dialed. It is nil when the host could
	// not be resolved or was invalid.
	IP net.IP

	// Port is the destination TCP port.
	Port uint16

	// State is the classified outcome of the check.
	State State

	// Duration is the time spent on the connect attempt. It is zero for
	// results that were produced without a dial (resolution failures and
	// canceled checks that never started).
	Duration time.Duration

	// Err is nil for StateOpen. For other states it carries the original
	// error (or the context error / resolution error) and can be inspected
	// with errors.Is and errors.As.
	Err error
}

// Scanner performs TCP connect scans. It is immutable after New and safe for
// concurrent use by multiple goroutines; a single instance can be reused for
// any number of scans.
type Scanner struct {
	concurrency    int
	connectTimeout time.Duration
	resolver       Resolver
	dial           dialFunc
}

// New creates a Scanner. The returned error reports invalid option values.
func New(opts ...Option) (*Scanner, error) {
	cfg := config{
		concurrency:    defaultConcurrency,
		connectTimeout: defaultConnectTimeout,
		resolver:       net.DefaultResolver,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}

	switch {
	case cfg.concurrency < 1:
		return nil, fmt.Errorf("%w: %d", ErrInvalidConcurrency, cfg.concurrency)
	case cfg.connectTimeout <= 0:
		return nil, fmt.Errorf("%w: %s", ErrInvalidTimeout, cfg.connectTimeout)
	case cfg.resolver == nil:
		return nil, ErrInvalidResolver
	}

	s := &Scanner{
		concurrency:    cfg.concurrency,
		connectTimeout: cfg.connectTimeout,
		resolver:       cfg.resolver,
		dial:           cfg.dial,
	}
	if s.dial == nil {
		dialer := &net.Dialer{Timeout: cfg.connectTimeout}
		s.dial = dialer.DialContext
	}
	return s, nil
}

// Scan checks every combination of host, resolved IP address and port, and
// returns a channel of results. The channel is closed when the scan is
// finished. Result order is not specified.
//
// Scan returns an error without starting any network activity when the context
// is nil or already done, when the host list is empty, when the port set is
// empty or invalid, or when the context is canceled during DNS resolution.
//
// A caller that stops receiving must cancel ctx: the scan goroutines block on
// delivery (backpressure) until the context is canceled, which keeps memory
// usage bounded.
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports PortSet) (<-chan Result, error) {
	_, out, err := s.start(ctx, hosts, ports)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ScanAll is a convenience wrapper around Scan that drains the result channel
// and returns a slice sorted by host, IP address and port.
//
// If the context is canceled during the scan, ScanAll returns exactly one
// result for every requested host/IP/port combination: completed checks keep
// their real state and the missing ones are reported as StateCanceled. The
// returned error is non-nil only for setup failures.
func (s *Scanner) ScanAll(ctx context.Context, hosts []string, ports PortSet) ([]Result, error) {
	plan, out, err := s.start(ctx, hosts, ports)
	if err != nil {
		return nil, err
	}

	results := make([]Result, 0, plan.resultCount())
	for result := range out {
		results = append(results, result)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		results = plan.fillMissing(results, ctxErr)
	}
	sortResults(results)
	return results, nil
}

// job is a single host/IP/port combination.
type job struct {
	host string
	ip   net.IP
	port uint16
}

// scanPlan describes a validated scan and is fixed before the scan starts.
type scanPlan struct {
	targets []hostTarget
	ports   []uint16
}

// start validates the input, resolves hosts and launches the scan goroutines.
func (s *Scanner) start(ctx context.Context, hosts []string, ports PortSet) (*scanPlan, <-chan Result, error) {
	if ctx == nil {
		return nil, nil, ErrNilContext
	}
	if err := ports.validate(); err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	targets, err := s.resolveTargets(ctx, hosts)
	if err != nil {
		return nil, nil, err
	}

	plan := &scanPlan{targets: targets, ports: ports.ports}
	out := make(chan Result, s.concurrency)
	go s.run(ctx, plan, out)
	return plan, out, nil
}

// run drives the scan: a fixed pool of workers consumes jobs produced by feed,
// and the results channel is closed exactly once after every worker exits.
func (s *Scanner) run(ctx context.Context, plan *scanPlan, out chan<- Result) {
	defer close(out)

	jobs := make(chan job, s.concurrency)
	var wg sync.WaitGroup
	wg.Add(s.concurrency)
	for range s.concurrency {
		go func() {
			defer wg.Done()
			s.work(ctx, jobs, out)
		}()
	}

	s.feed(ctx, plan, jobs, out)
	close(jobs)
	wg.Wait()
}

// feed emits jobs until the plan is exhausted or the context is canceled.
// Hosts that failed to resolve are reported immediately, without a job.
func (s *Scanner) feed(ctx context.Context, plan *scanPlan, jobs chan<- job, out chan<- Result) {
	for _, target := range plan.targets {
		if target.err != nil {
			for _, port := range plan.ports {
				result := Result{Host: target.host, Port: port, State: StateError, Err: target.err}
				if !send(ctx, out, result) {
					return
				}
			}
			continue
		}
		for _, ip := range target.ips {
			for _, port := range plan.ports {
				select {
				case jobs <- job{host: target.host, ip: ip, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

// work consumes jobs and publishes one result per job.
func (s *Scanner) work(ctx context.Context, jobs <-chan job, out chan<- Result) {
	for j := range jobs {
		send(ctx, out, s.check(ctx, j))
	}
}

// check performs a single TCP connect attempt and classifies its outcome.
func (s *Scanner) check(ctx context.Context, j job) Result {
	address := net.JoinHostPort(j.ip.String(), strconv.Itoa(int(j.port)))
	start := time.Now()
	conn, err := s.dial(ctx, "tcp", address)
	duration := time.Since(start)

	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		return Result{
			Host:     j.host,
			IP:       cloneIP(j.ip),
			Port:     j.port,
			State:    StateOpen,
			Duration: duration,
		}
	}
	return Result{
		Host:     j.host,
		IP:       cloneIP(j.ip),
		Port:     j.port,
		State:    classifyDialError(err, ctx.Err()),
		Duration: duration,
		Err:      err,
	}
}

// send delivers a result, preferring an available buffer slot. When the
// consumer is slow it blocks until the result is delivered or the context is
// canceled; the last attempt after cancellation is best-effort so that a
// completed check is not thrown away gratuitously.
func send(ctx context.Context, out chan<- Result, result Result) bool {
	select {
	case out <- result:
		return true
	default:
	}

	select {
	case out <- result:
		return true
	case <-ctx.Done():
		select {
		case out <- result:
			return true
		default:
			return false
		}
	}
}

// resultCount is the number of results ScanAll must return.
func (p *scanPlan) resultCount() int {
	count := 0
	for _, target := range p.targets {
		if target.err != nil {
			count += len(p.ports)
			continue
		}
		count += len(target.ips) * len(p.ports)
	}
	return count
}

// fillMissing appends Canceled results (or host-level errors) for combinations
// that were never reported because the scan was canceled.
func (p *scanPlan) fillMissing(results []Result, ctxErr error) []Result {
	seen := make(map[string]struct{}, len(results))
	for _, result := range results {
		seen[resultKey(result.Host, result.IP, result.Port)] = struct{}{}
	}

	for _, target := range p.targets {
		if target.err != nil {
			for _, port := range p.ports {
				if _, ok := seen[resultKey(target.host, nil, port)]; ok {
					continue
				}
				results = append(results, Result{
					Host:  target.host,
					Port:  port,
					State: StateError,
					Err:   target.err,
				})
			}
			continue
		}
		for _, ip := range target.ips {
			for _, port := range p.ports {
				if _, ok := seen[resultKey(target.host, ip, port)]; ok {
					continue
				}
				results = append(results, Result{
					Host:  target.host,
					IP:    cloneIP(ip),
					Port:  port,
					State: StateCanceled,
					Err:   ctxErr,
				})
			}
		}
	}
	return results
}

func resultKey(host string, ip net.IP, port uint16) string {
	return host + "\x00" + ipKey(ip) + "\x00" + strconv.Itoa(int(port))
}

func ipKey(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// cloneIP returns an independent copy so that a caller mutating Result.IP
// cannot affect other results of the same scan.
func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return slices.Clone(ip)
}

func sortResults(results []Result) {
	slices.SortFunc(results, func(a, b Result) int {
		if c := cmp.Compare(a.Host, b.Host); c != 0 {
			return c
		}
		if c := cmp.Compare(ipKey(a.IP), ipKey(b.IP)); c != 0 {
			return c
		}
		return cmp.Compare(a.Port, b.Port)
	})
}

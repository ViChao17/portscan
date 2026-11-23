package portscan

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeResolver is a configurable Resolver for tests.
type fakeResolver struct {
	mu    sync.Mutex
	addrs map[string][]net.IPAddr
	errs  map[string]error
	calls map[string]int
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		addrs: make(map[string][]net.IPAddr),
		errs:  make(map[string]error),
		calls: make(map[string]int),
	}
}

func (f *fakeResolver) set(host string, ips ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	addrs := make([]net.IPAddr, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, net.IPAddr{IP: net.ParseIP(ip)})
	}
	f.addrs[host] = addrs
}

func (f *fakeResolver) setErr(host string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[host] = err
}

func (f *fakeResolver) callCount(host string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[host]
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	f.mu.Lock()
	f.calls[host]++
	err := f.errs[host]
	addrs := append([]net.IPAddr(nil), f.addrs[host]...)
	f.mu.Unlock()

	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return addrs, nil
}

// timeoutErr simulates a network timeout.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

// collect drains a result channel with a safety timeout.
func collect(t *testing.T, ch <-chan Result) []Result {
	t.Helper()
	var results []Result
	deadline := time.After(10 * time.Second)
	for {
		select {
		case result, ok := <-ch:
			if !ok {
				return results
			}
			results = append(results, result)
		case <-deadline:
			t.Fatalf("timed out waiting for the results channel to close, got %d results", len(results))
		}
	}
}

// mustNew builds a Scanner or fails the test.
func mustNew(t *testing.T, opts ...Option) *Scanner {
	t.Helper()
	scanner, err := New(opts...)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return scanner
}

// openListener starts a TCP listener on the loopback interface and returns its
// port. The listener is closed at the end of the test.
func openListener(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

// closedPort returns a loopback port that is not listening.
func closedPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return port
}

// findResult returns the first result matching host, port and, when ip is not
// nil, the IP address.
func findResult(results []Result, host string, port uint16, ip net.IP) (Result, bool) {
	for _, result := range results {
		if result.Host != host || result.Port != port {
			continue
		}
		if ip != nil && (result.IP == nil || !result.IP.Equal(ip)) {
			continue
		}
		return result, true
	}
	return Result{}, false
}

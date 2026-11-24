package portscan

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestScanOpenAndClosed(t *testing.T) {
	openPort := openListener(t)
	closedPortNumber := closedPort(t)

	scanner := mustNew(t, WithConcurrency(4), WithConnectTimeout(time.Second))
	results := collect(t, mustScan(t, scanner, context.Background(), []string{"127.0.0.1"}, Ports(openPort, closedPortNumber)))

	if len(results) != 2 {
		t.Fatalf("got %d results, want 2: %+v", len(results), results)
	}

	openResult, ok := findResult(results, "127.0.0.1", openPort, nil)
	if !ok {
		t.Fatalf("missing result for open port %d", openPort)
	}
	if openResult.State != StateOpen {
		t.Fatalf("open port state = %v (err %v), want open", openResult.State, openResult.Err)
	}
	if openResult.Err != nil {
		t.Fatalf("open port Err = %v, want nil", openResult.Err)
	}
	if openResult.IP == nil || !openResult.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("open port IP = %v, want 127.0.0.1", openResult.IP)
	}

	closedResult, ok := findResult(results, "127.0.0.1", closedPortNumber, nil)
	if !ok {
		t.Fatalf("missing result for closed port %d", closedPortNumber)
	}
	if closedResult.State != StateClosed {
		t.Fatalf("closed port state = %v (err %v), want closed", closedResult.State, closedResult.Err)
	}
	if closedResult.Err == nil {
		t.Fatal("closed port Err = nil, want the original dial error")
	}
}

func TestScanClosesConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	scanner := mustNew(t)
	results := collect(t, mustScan(t, scanner, context.Background(), []string{"127.0.0.1"}, Ports(port)))
	if len(results) != 1 || results[0].State != StateOpen {
		t.Fatalf("results = %+v, want one open result", results)
	}

	select {
	case conn := <-accepted:
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, readErr := conn.Read(make([]byte, 1))
		if !errors.Is(readErr, io.EOF) {
			t.Fatalf("read from accepted connection = %v, want io.EOF (connection must be closed by the scanner)", readErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not accept the scanned connection")
	}
}

func TestScanIPv6(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback is not available: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	scanner := mustNew(t)
	// Both spellings of the same address must collapse into one target.
	results := collect(t, mustScan(t, scanner, context.Background(), []string{"::1", "[::1]"}, Ports(port)))

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(results), results)
	}
	if results[0].State != StateOpen {
		t.Fatalf("state = %v (err %v), want open", results[0].State, results[0].Err)
	}
	if !results[0].IP.Equal(net.ParseIP("::1")) {
		t.Fatalf("IP = %v, want ::1", results[0].IP)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	const (
		limit     = 7
		portCount = 200
	)

	var inFlight, maxInFlight atomic.Int64
	dial := func(context.Context, string, string) (net.Conn, error) {
		current := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			max := maxInFlight.Load()
			if current <= max || maxInFlight.CompareAndSwap(max, current) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		return nil, errors.New("fake: connection refused")
	}

	scanner := mustNew(t, WithConcurrency(limit), withDialer(dial))
	results := collect(t, mustScan(t, scanner, context.Background(), []string{"127.0.0.1"}, Range(1, portCount)))

	if len(results) != portCount {
		t.Fatalf("got %d results, want %d", len(results), portCount)
	}
	if got := maxInFlight.Load(); got > limit {
		t.Fatalf("max in-flight dials = %d, want at most %d", got, limit)
	}
	if got := maxInFlight.Load(); got < 2 {
		t.Fatalf("max in-flight dials = %d, checks did not run concurrently", got)
	}
}

func TestScanTimeoutState(t *testing.T) {
	scanner := mustNew(t, withDialer(func(context.Context, string, string) (net.Conn, error) {
		return nil, timeoutErr{}
	}))

	results := collect(t, mustScan(t, scanner, context.Background(), []string{"127.0.0.1"}, Ports(80)))
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].State != StateTimeout {
		t.Fatalf("state = %v, want timeout", results[0].State)
	}
}

func TestScanCancelInFlight(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	scanner := mustNew(t, WithConcurrency(8), withDialer(dial))
	ch, err := scanner.Scan(ctx, []string{"127.0.0.1"}, Range(1, 100))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	time.AfterFunc(30*time.Millisecond, cancel)
	results := collect(t, ch)

	if len(results) == 0 {
		t.Fatal("got no results, want canceled results for in-flight checks")
	}
	if len(results) > 100 {
		t.Fatalf("got %d results, want at most 100", len(results))
	}
	for _, result := range results {
		if result.State != StateCanceled {
			t.Fatalf("state = %v (err %v), want canceled", result.State, result.Err)
		}
		if !errors.Is(result.Err, context.Canceled) {
			t.Fatalf("Err = %v, want context.Canceled", result.Err)
		}
	}
}

func TestScanCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	scanner := mustNew(t)
	ch, err := scanner.Scan(ctx, []string{"127.0.0.1"}, Ports(80))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan() error = %v, want context.Canceled", err)
	}
	if ch != nil {
		t.Fatal("Scan() returned a channel together with an error")
	}
}

func TestScanNilContext(t *testing.T) {
	scanner := mustNew(t)
	//nolint:staticcheck // nil context is exactly what is being tested
	ch, err := scanner.Scan(nil, []string{"127.0.0.1"}, Ports(80))
	if !errors.Is(err, ErrNilContext) {
		t.Fatalf("Scan() error = %v, want ErrNilContext", err)
	}
	if ch != nil {
		t.Fatal("Scan() returned a channel together with an error")
	}
}

func TestScanCancellationDuringResolution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	started := make(chan struct{})
	resolver := &blockingResolver{started: started}

	scanner := mustNew(t, WithResolver(resolver))
	go func() {
		<-started
		cancel()
	}()

	if _, err := scanner.Scan(ctx, []string{"slow.test"}, Ports(80)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan() error = %v, want context.Canceled", err)
	}
}

func TestValidationErrors(t *testing.T) {
	scanner := mustNew(t)
	cases := []struct {
		name  string
		hosts []string
		ports PortSet
		want  error
	}{
		{name: "no hosts", hosts: nil, ports: Ports(80), want: ErrNoHosts},
		{name: "empty hosts", hosts: []string{}, ports: Ports(80), want: ErrNoHosts},
		{name: "no ports", hosts: []string{"127.0.0.1"}, ports: PortSet{}, want: ErrNoPorts},
		{name: "port zero", hosts: []string{"127.0.0.1"}, ports: Ports(0), want: ErrInvalidPort},
		{name: "reversed range", hosts: []string{"127.0.0.1"}, ports: Range(1000, 1), want: ErrInvalidRange},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch, err := scanner.Scan(context.Background(), tc.hosts, tc.ports)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Scan() error = %v, want %v", err, tc.want)
			}
			if ch != nil {
				t.Fatal("Scan() returned a channel together with an error")
			}
			if _, err := scanner.ScanAll(context.Background(), tc.hosts, tc.ports); !errors.Is(err, tc.want) {
				t.Fatalf("ScanAll() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestInvalidHostsReportedPerPort(t *testing.T) {
	scanner := mustNew(t, withDialer(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("must not be dialed")
	}))

	results := collect(t, mustScan(t, scanner, context.Background(), []string{"", "999.1.1.1"}, Ports(80, 443)))
	if len(results) != 4 {
		t.Fatalf("got %d results, want 4: %+v", len(results), results)
	}
	for _, result := range results {
		if result.State != StateError {
			t.Fatalf("state = %v, want error", result.State)
		}
		if !errors.Is(result.Err, ErrInvalidHost) {
			t.Fatalf("Err = %v, want ErrInvalidHost", result.Err)
		}
		if result.IP != nil {
			t.Fatalf("IP = %v, want nil for an invalid host", result.IP)
		}
	}
}

func TestUnresolvableHostDoesNotAbortScan(t *testing.T) {
	openPort := openListener(t)

	resolver := newFakeResolver()
	resolver.setErr("bad.test", &net.DNSError{Err: "no such host", Name: "bad.test", IsNotFound: true})
	resolver.set("good.test", "127.0.0.1")

	scanner := mustNew(t, WithResolver(resolver), WithConcurrency(4))
	results := collect(t, mustScan(t, scanner, context.Background(), []string{"bad.test", "good.test"}, Ports(openPort, 81)))

	if len(results) != 4 {
		t.Fatalf("got %d results, want 4: %+v", len(results), results)
	}

	for _, port := range []uint16{openPort, 81} {
		bad, ok := findResult(results, "bad.test", port, nil)
		if !ok {
			t.Fatalf("missing error result for bad.test:%d", port)
		}
		if bad.State != StateError {
			t.Fatalf("bad.test:%d state = %v, want error", port, bad.State)
		}
		if !errors.Is(bad.Err, ErrResolveFailed) {
			t.Fatalf("bad.test:%d Err = %v, want ErrResolveFailed", port, bad.Err)
		}

		good, ok := findResult(results, "good.test", port, net.ParseIP("127.0.0.1"))
		if !ok {
			t.Fatalf("missing result for good.test:%d", port)
		}
		if port == openPort && good.State != StateOpen {
			t.Fatalf("good.test:%d state = %v, want open", port, good.State)
		}
	}
}

func TestDuplicateHostsAreScannedOnce(t *testing.T) {
	resolver := newFakeResolver()
	resolver.set("dup.test", "127.0.0.1")

	scanner := mustNew(t, WithResolver(resolver), withDialer(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("fake: connection refused")
	}))

	results := collect(t, mustScan(t, scanner, context.Background(),
		[]string{"dup.test", "DUP.test", " dup.test "}, Range(80, 82)))

	if len(results) != 3 {
		t.Fatalf("got %d results, want 3: %+v", len(results), results)
	}
	if got := resolver.callCount("dup.test"); got != 1 {
		t.Fatalf("resolver calls = %d, want 1", got)
	}
	for _, result := range results {
		if result.Host != "dup.test" {
			t.Fatalf("Host = %q, want the first spelling %q", result.Host, "dup.test")
		}
	}
}

func TestMultipleAddressesProduceResultPerIP(t *testing.T) {
	resolver := newFakeResolver()
	resolver.set("multi.test", "127.0.0.1", "127.0.0.2")

	scanner := mustNew(t, WithResolver(resolver), withDialer(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("fake: connection refused")
	}))

	results := collect(t, mustScan(t, scanner, context.Background(), []string{"multi.test"}, Range(80, 81)))
	if len(results) != 4 {
		t.Fatalf("got %d results, want 4: %+v", len(results), results)
	}

	ips := make(map[string]int)
	for _, result := range results {
		ips[result.IP.String()]++
	}
	if ips["127.0.0.1"] != 2 || ips["127.0.0.2"] != 2 {
		t.Fatalf("IP distribution = %v, want 2 results per address", ips)
	}
}

func TestScanAllSortedAndComplete(t *testing.T) {
	resolver := newFakeResolver()
	resolver.set("b.test", "127.0.0.1")
	resolver.set("a.test", "127.0.0.1")

	scanner := mustNew(t, WithResolver(resolver), withDialer(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("fake: connection refused")
	}))

	results, err := scanner.ScanAll(context.Background(), []string{"b.test", "a.test"}, Ports(443, 80))
	if err != nil {
		t.Fatalf("ScanAll() error = %v", err)
	}

	want := []struct {
		host string
		port uint16
	}{
		{"a.test", 80},
		{"a.test", 443},
		{"b.test", 80},
		{"b.test", 443},
	}
	if len(results) != len(want) {
		t.Fatalf("got %d results, want %d", len(results), len(want))
	}
	for i, expected := range want {
		if results[i].Host != expected.host || results[i].Port != expected.port {
			t.Fatalf("results[%d] = %s:%d, want %s:%d", i, results[i].Host, results[i].Port, expected.host, expected.port)
		}
	}
}

func TestScanAllCanceledFillsMissingResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	scanner := mustNew(t, WithConcurrency(8), withDialer(dial))
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	results, err := scanner.ScanAll(ctx, []string{"127.0.0.1"}, Range(1, 50))
	if err != nil {
		t.Fatalf("ScanAll() error = %v", err)
	}
	if len(results) != 50 {
		t.Fatalf("got %d results, want 50", len(results))
	}
	for _, result := range results {
		if result.State != StateCanceled {
			t.Fatalf("state = %v, want canceled", result.State)
		}
		if !errors.Is(result.Err, context.Canceled) {
			t.Fatalf("Err = %v, want context.Canceled", result.Err)
		}
	}
}

func TestScannerReuseAndConcurrentScans(t *testing.T) {
	scanner := mustNew(t, WithConcurrency(4), withDialer(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("fake: connection refused")
	}))

	if results := collect(t, mustScan(t, scanner, context.Background(), []string{"127.0.0.1"}, Range(1, 10))); len(results) != 10 {
		t.Fatalf("first scan: got %d results, want 10", len(results))
	}
	if results := collect(t, mustScan(t, scanner, context.Background(), []string{"127.0.0.2"}, Range(1, 5))); len(results) != 5 {
		t.Fatalf("second scan: got %d results, want 5", len(results))
	}

	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			host := "127.0.0." + string(rune('1'+i))
			results, err := scanner.ScanAll(context.Background(), []string{host}, Range(1, 5))
			if err != nil {
				t.Errorf("concurrent ScanAll() error = %v", err)
				return
			}
			if len(results) != 5 {
				t.Errorf("concurrent scan: got %d results, want 5", len(results))
			}
		}()
	}
	wg.Wait()
}

func TestSlowConsumer(t *testing.T) {
	scanner := mustNew(t, WithConcurrency(2), withDialer(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("fake: connection refused")
	}))

	ch, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, Range(1, 30))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	deadline := time.After(10 * time.Second)
	count := 0
	for count < 30 {
		select {
		case _, ok := <-ch:
			if !ok {
				t.Fatalf("channel closed after %d results, want 30", count)
			}
			count++
		case <-deadline:
			t.Fatalf("timed out after %d results, want 30", count)
		}
		time.Sleep(2 * time.Millisecond)
	}

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("got more results than requested")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("results channel was not closed")
	}
}

func TestNewValidatesOptions(t *testing.T) {
	cases := []struct {
		name string
		opt  Option
		want error
	}{
		{name: "zero concurrency", opt: WithConcurrency(0), want: ErrInvalidConcurrency},
		{name: "negative concurrency", opt: WithConcurrency(-1), want: ErrInvalidConcurrency},
		{name: "zero timeout", opt: WithConnectTimeout(0), want: ErrInvalidTimeout},
		{name: "negative timeout", opt: WithConnectTimeout(-time.Second), want: ErrInvalidTimeout},
		{name: "nil resolver", opt: WithResolver(nil), want: ErrInvalidResolver},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.opt); !errors.Is(err, tc.want) {
				t.Fatalf("New() error = %v, want %v", err, tc.want)
			}
		})
	}

	if _, err := New(nil); err != nil {
		t.Fatalf("New(nil) error = %v, want nil", err)
	}
}

func TestResultDurationIsMeasured(t *testing.T) {
	scanner := mustNew(t, withDialer(func(context.Context, string, string) (net.Conn, error) {
		time.Sleep(3 * time.Millisecond)
		return nil, errors.New("fake: connection refused")
	}))

	results := collect(t, mustScan(t, scanner, context.Background(), []string{"127.0.0.1"}, Ports(80)))
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Duration < 2*time.Millisecond {
		t.Fatalf("Duration = %v, want at least 2ms", results[0].Duration)
	}
}

func TestResultIPIsCopyOfTarget(t *testing.T) {
	scanner := mustNew(t, withDialer(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("fake: connection refused")
	}))

	results := collect(t, mustScan(t, scanner, context.Background(), []string{"127.0.0.1"}, Ports(80, 81)))
	if len(results) != 2 || !results[0].IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("results = %+v, want two results with IP 127.0.0.1", results)
	}

	// Results must not share the same IP slice.
	results[0].IP[0] = 10
	if results[1].IP.Equal(net.IP{10, 0, 0, 1}) {
		t.Fatal("mutating one Result.IP changed another result")
	}
}

func TestDialAddressFormat(t *testing.T) {
	var address string
	scanner := mustNew(t, withDialer(func(_ context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" {
			t.Errorf("network = %q, want tcp", network)
		}
		address = addr
		return nil, errors.New("fake: connection refused")
	}))

	collect(t, mustScan(t, scanner, context.Background(), []string{"::1"}, Ports(443)))
	if address != "[::1]:443" {
		t.Fatalf("dial address = %q, want %q", address, "[::1]:443")
	}
}

// blockingResolver blocks until ctx is canceled.
type blockingResolver struct {
	started chan struct{}
}

func (r *blockingResolver) LookupIPAddr(ctx context.Context, _ string) ([]net.IPAddr, error) {
	close(r.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func mustScan(t *testing.T, scanner *Scanner, ctx context.Context, hosts []string, ports PortSet) <-chan Result {
	t.Helper()
	ch, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	return ch
}

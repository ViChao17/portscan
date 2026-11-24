package portscan

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

func TestCompletedResultsSurviveCancellationWithFullBuffer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var completed atomic.Int64
		scanner := mustNew(t, WithConcurrency(1), withDialer(func(context.Context, string, string) (net.Conn, error) {
			completed.Add(1)
			client, peer := net.Pipe()
			_ = peer.Close()
			return client, nil
		}))
		plan := &scanPlan{
			targets: []hostTarget{{host: "127.0.0.1", ips: []net.IP{net.ParseIP("127.0.0.1")}}},
			ports:   []uint16{80, 81},
		}
		out := make(chan Result, 1)
		go scanner.run(ctx, plan, out, deliveryGuaranteed)

		// Hold the collector until one result fills the buffer and the next
		// completed check is blocked on delivery. No timing assumptions.
		synctest.Wait()
		if got := completed.Load(); got != 2 {
			t.Fatalf("completed checks = %d, want 2 before cancellation", got)
		}
		cancel()
		synctest.Wait()

		results := collect(t, out)
		if len(results) != 2 {
			t.Fatalf("got %d completed results, want 2: %+v", len(results), results)
		}
		for _, port := range []uint16{80, 81} {
			result, ok := findResult(results, "127.0.0.1", port, nil)
			if !ok || result.State != StateOpen || result.Err != nil {
				t.Errorf("port %d: result = %+v, present = %t, want open with no error", port, result, ok)
			}
		}
	})
}

func TestScanAllDoesNotDialQueuedJobsAfterCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var attempts atomic.Int64
		scanner := mustNew(t, WithConcurrency(1), withDialer(func(ctx context.Context, _, _ string) (net.Conn, error) {
			attempts.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		}))

		var results []Result
		var scanErr error
		done := make(chan struct{})
		go func() {
			defer close(done)
			results, scanErr = scanner.ScanAll(ctx, []string{"127.0.0.1"}, Range(80, 84))
		}()

		// The first dial is in flight, another job is buffered, and the
		// producer is waiting for room in the job queue.
		synctest.Wait()
		if got := attempts.Load(); got != 1 {
			t.Fatalf("dial attempts before cancellation = %d, want 1", got)
		}
		cancel()
		<-done

		if scanErr != nil {
			t.Fatalf("ScanAll() error = %v", scanErr)
		}
		if got := attempts.Load(); got != 1 {
			t.Errorf("dial attempts = %d, want only the one started before cancellation", got)
		}
		if len(results) != 5 {
			t.Fatalf("got %d results, want 5", len(results))
		}
		for _, result := range results {
			if result.State != StateCanceled || !errors.Is(result.Err, context.Canceled) {
				t.Errorf("result = %+v, want canceled with context.Canceled", result)
			}
		}
	})
}

func TestScanExitsAfterCancellationWithoutConsumer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var completed atomic.Int64
		scanner := mustNew(t, WithConcurrency(1), withDialer(func(context.Context, string, string) (net.Conn, error) {
			completed.Add(1)
			client, peer := net.Pipe()
			_ = peer.Close()
			return client, nil
		}))

		if _, err := scanner.Scan(ctx, []string{"127.0.0.1"}, Range(80, 84)); err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		synctest.Wait()
		if got := completed.Load(); got != 2 {
			t.Fatalf("completed checks = %d, want 2 with delivery blocked", got)
		}
		cancel()
		synctest.Wait()
		// Never drain the output. synctest.Test requires every goroutine to
		// exit when this function returns, exposing any blocked sender.
	})
}

func TestFeedDoesNotPublishHostErrorsAfterObservedCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scanner := mustNew(t)
	plan := &scanPlan{
		targets: []hostTarget{{host: "", err: ErrInvalidHost}},
		ports:   []uint16{80, 81},
	}
	jobs := make(chan job, 2)
	out := make(chan Result, 2)
	scanner.feed(ctx, plan, jobs, out, deliveryCancelable)
	if got := len(out); got != 0 {
		t.Fatalf("published %d host errors after observing cancellation, want 0", got)
	}
}
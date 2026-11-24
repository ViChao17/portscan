package portscan

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
)

func TestScanKeepsRelativeAndAbsoluteDNSNamesDistinct(t *testing.T) {
	resolver := newFakeResolver()
	resolver.set("dup.test", "127.0.0.1")
	resolver.set("dup.test.", "127.0.0.2")
	scanner := mustNew(t, WithResolver(resolver), withDialer(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("test dial error")
	}))

	results, err := scanner.ScanAll(context.Background(),
		[]string{"dup.test", "DUP.test", "dup.test.", "DUP.test."}, Ports(80))
	if err != nil {
		t.Fatalf("ScanAll() error = %v, want nil", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want separate relative and absolute targets: %+v", len(results), results)
	}
	for _, tc := range []struct{ host, ip string }{
		{host: "dup.test", ip: "127.0.0.1"},
		{host: "dup.test.", ip: "127.0.0.2"},
	} {
		if _, ok := findResult(results, tc.host, 80, net.ParseIP(tc.ip)); !ok {
			t.Errorf("missing result for %s at %s: %+v", tc.host, tc.ip, results)
		}
		if got := resolver.callCount(tc.host); got != 1 {
			t.Errorf("resolver calls for %q = %d, want 1", tc.host, got)
		}
	}
}

func TestResolveTargetsCancellationWaitsForActiveLookups(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const concurrency = 2
		hosts := []string{"one.test", "two.test", "three.test", "four.test", "five.test"}
		started := make(chan string, len(hosts))
		exited := make(chan string, len(hosts))
		release := make(chan struct{})
		finishLookups := sync.OnceFunc(func() { close(release) })
		defer finishLookups()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		resolver := targetsResolverFunc(func(lookupCtx context.Context, host string) ([]net.IPAddr, error) {
			started <- host
			<-lookupCtx.Done()
			// Let the test observe cancellation before each active lookup finishes.
			<-release
			exited <- host
			return nil, lookupCtx.Err()
		})
		scanner := mustNew(t, WithResolver(resolver), WithConcurrency(concurrency))
		done := make(chan error, 1)
		go func() {
			_, err := scanner.resolveTargets(ctx, hosts)
			done <- err
		}()

		synctest.Wait()
		if got := len(started); got != concurrency {
			t.Fatalf("active DNS lookups = %d, want configured concurrency %d", got, concurrency)
		}
		cancel()
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("resolveTargets returned before active lookups finished: %v", err)
		default:
		}

		finishLookups()
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("resolveTargets() error = %v, want context.Canceled", err)
			}
		default:
			t.Fatal("resolveTargets did not return after all active lookups finished")
		}
		if got := len(started); got != concurrency {
			t.Errorf("DNS lookups started after cancellation: total = %d, want %d", got, concurrency)
		}
		if got := len(exited); got != concurrency {
			t.Errorf("completed DNS lookups = %d, want %d", got, concurrency)
		}
	})
}

type targetsResolverFunc func(context.Context, string) ([]net.IPAddr, error)

func (f targetsResolverFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}
// Package portscan implements concurrent TCP connect scanning of ports on one
// or more hosts.
//
// The package contains no CLI, HTTP, database or message-broker code and can be
// embedded into any Go application. It uses only the standard library.
//
// # Basic usage
//
//	scanner, err := portscan.New(
//		portscan.WithConcurrency(100),
//		portscan.WithConnectTimeout(500*time.Millisecond),
//	)
//	if err != nil {
//		return err
//	}
//
//	results, err := scanner.Scan(ctx, []string{"192.168.1.10"}, portscan.Range(1, 1000))
//	if err != nil {
//		return err
//	}
//	for result := range results {
//		fmt.Printf("%s:%d %s\n", result.Host, result.Port, result.State)
//	}
//
// # Results
//
// Scan returns a channel of Result values. The channel is closed after all
// checks are finished. Result order is not specified; use ScanAll if a
// deterministic sorted slice is required.
//
// A Scanner is immutable after New and is safe for concurrent use by multiple
// goroutines.
//
// # Cancellation
//
// Cancellation is cooperative and driven by context.Context. After the context
// is canceled no new checks are started, in-flight dials are aborted, the
// results channel is closed, and checks that were in flight report
// StateCanceled. Ports that were never started are not reported by Scan.
// ScanAll fills such gaps with StateCanceled results.
//
// A caller that stops reading from the results channel must cancel the context;
// otherwise the scan goroutines block on delivery (backpressure) until it is
// canceled. This bounds memory usage regardless of the number of targets.
//
// # Errors
//
// Problems with the scan configuration (no hosts, empty port set, invalid port,
// reversed range, invalid option values) are returned from Scan/ScanAll before
// any network activity starts. Failures related to a single host (an empty or
// malformed address, an unresolvable DNS name) do not abort the whole scan:
// every requested port of that host is reported once with StateError and Err
// describing the reason. Use errors.Is to inspect the cause.
package portscan

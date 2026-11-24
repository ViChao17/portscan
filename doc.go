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
// Cancellation is cooperative and driven by context.Context. Producers and
// workers stop dispatching checks once they observe cancellation; the same
// context also interrupts in-flight network operations. The results channel
// is closed after all senders finish. Scan delivers remaining results on a
// best-effort basis after cancellation and does not report unstarted checks.
// ScanAll keeps every completed result and fills unreported combinations with
// StateCanceled (or the corresponding host-level resolution error).
//
// A caller that stops reading from the results channel must cancel the context;
// otherwise the scan goroutines block on delivery (backpressure) until it is
// canceled. Work and result queues are bounded by the configured concurrency;
// target storage still grows with the input. ScanAll additionally stores the
// full result set. Concurrency limits apply independently to each scan call.
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

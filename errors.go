package portscan

import "errors"

// Configuration and input errors returned by New, Scan and ScanAll.
//
// These sentinels are meant to be inspected with errors.Is; error messages are
// not part of the API contract.
var (
	// ErrNoHosts is returned when the host list is empty.
	ErrNoHosts = errors.New("portscan: no hosts to scan")

	// ErrNoPorts is returned when the port set is empty.
	ErrNoPorts = errors.New("portscan: no ports to scan")

	// ErrInvalidHost is reported for an empty host or a malformed IP literal.
	// It is never returned from Scan directly; it is wrapped in Result.Err for
	// each port of the offending host.
	ErrInvalidHost = errors.New("portscan: invalid host")

	// ErrInvalidPort is returned for port 0 or a range containing port 0.
	ErrInvalidPort = errors.New("portscan: invalid port")

	// ErrInvalidRange is returned for a reversed port range.
	ErrInvalidRange = errors.New("portscan: invalid port range")

	// ErrInvalidPortSet is returned by ParsePorts for malformed input.
	ErrInvalidPortSet = errors.New("portscan: invalid port specification")

	// ErrInvalidConcurrency is returned when the concurrency limit is below 1.
	ErrInvalidConcurrency = errors.New("portscan: invalid concurrency")

	// ErrInvalidTimeout is returned when the connect timeout is not positive.
	ErrInvalidTimeout = errors.New("portscan: invalid connect timeout")

	// ErrInvalidResolver is returned when a nil resolver is supplied.
	ErrInvalidResolver = errors.New("portscan: invalid resolver")

	// ErrResolveFailed is wrapped in Result.Err when a DNS name cannot be
	// resolved. The underlying resolver error is available via errors.Unwrap.
	ErrResolveFailed = errors.New("portscan: host resolution failed")

	// ErrNilContext is returned when a nil context is passed to Scan/ScanAll.
	ErrNilContext = errors.New("portscan: nil context")
)

// ResolveError describes a failure to turn a host name into IP addresses.
type ResolveError struct {
	// Host is the host name exactly as it was supplied by the caller.
	Host string

	// Err is the underlying failure.
	Err error
}

// Error implements the error interface.
func (e *ResolveError) Error() string {
	return "portscan: resolve " + e.Host + ": " + e.Err.Error()
}

// Unwrap allows errors.Is/errors.As to inspect the underlying cause.
func (e *ResolveError) Unwrap() error { return e.Err }

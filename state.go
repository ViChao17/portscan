package portscan

// State describes the outcome of a single TCP connect attempt.
type State uint8

const (
	// StateOpen means the TCP handshake completed successfully.
	StateOpen State = iota + 1

	// StateClosed means the peer explicitly refused the connection
	// (for example, ECONNREFUSED on Unix or WSAECONNREFUSED on Windows).
	StateClosed

	// StateTimeout means the connect attempt did not finish within the
	// configured connect timeout.
	StateTimeout

	// StateUnreachable means the host or network is not reachable
	// (EHOSTUNREACH, ENETUNREACH, EHOSTDOWN, ENETDOWN and their Windows
	// equivalents).
	StateUnreachable

	// StateCanceled means the check was aborted because the context passed to
	// Scan/ScanAll was canceled or its deadline expired.
	StateCanceled

	// StateError means the check failed for any other reason; Result.Err
	// contains the original error.
	StateError
)

// String returns the lowercase name of the state, or "unknown" for values
// outside the defined set.
func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "closed"
	case StateTimeout:
		return "timeout"
	case StateUnreachable:
		return "unreachable"
	case StateCanceled:
		return "canceled"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

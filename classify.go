package portscan

import (
	"context"
	"errors"
	"net"
	"os"
)

// classifyDialError maps a dial error to a State without relying on error
// message text. ctxErr is the result of ctx.Err() at the time of the failure.
func classifyDialError(err error, ctxErr error) State {
	if err == nil {
		return StateOpen
	}
	switch {
	case isConnRefused(err):
		return StateClosed
	case isUnreachable(err):
		return StateUnreachable
	case ctxErr != nil:
		// A scan-wide cancellation explains the failure better than an
		// ambiguous socket error.
		return StateCanceled
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return StateCanceled
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StateTimeout
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return StateTimeout
	}
	return StateError
}

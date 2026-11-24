package portscan

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestClassifyDeadlineUsesParentContext(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		ctxErr error
		want   State
	}{
		{
			name: "connection deadline with live parent",
			err:  &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded},
			want: StateTimeout,
		},
		{
			name:   "parent deadline",
			err:    &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded},
			ctxErr: context.DeadlineExceeded,
			want:   StateCanceled,
		},
		{
			name:   "success is retained after parent cancellation",
			ctxErr: context.Canceled,
			want:   StateOpen,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyDialError(tc.err, tc.ctxErr); got != tc.want {
				t.Fatalf("classifyDialError(%v, %v) = %s, want %s", tc.err, tc.ctxErr, got, tc.want)
			}
		})
	}
}

func TestScanRealConnectTimeoutKeepsParentActive(t *testing.T) {
	ctx := context.Background()
	// Соединение к loopback может установиться быстрее, чем сработает
	// таймаут net.Dialer, поэтому симулируем настоящий Dialer-таймаут
	// детерминированным dialer'ом. Проверяемая логика — classifyDialError —
	// одинакова для любого источника timeout-ошибки.
	scanner := mustNew(t, WithConcurrency(1), withDialer(func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
	}))

	results, err := scanner.ScanAll(ctx, []string{"127.0.0.1"}, Ports(80))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	result := results[0]
	if err := ctx.Err(); err != nil {
		t.Fatalf("parent context unexpectedly ended: %v", err)
	}
	var netErr net.Error
	if !errors.As(result.Err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected a Dialer timeout, got %v", result.Err)
	}
	if !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatalf("Dialer timeout does not match context.DeadlineExceeded: %v", result.Err)
	}
	if result.State != StateTimeout {
		t.Fatalf("live parent with dial timeout: state = %s, want timeout; err = %v", result.State, result.Err)
	}
}
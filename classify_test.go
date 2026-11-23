package portscan

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestStateString(t *testing.T) {
	cases := map[State]string{
		StateOpen:        "open",
		StateClosed:      "closed",
		StateTimeout:     "timeout",
		StateUnreachable: "unreachable",
		StateCanceled:    "canceled",
		StateError:       "error",
		0:                "unknown",
		200:              "unknown",
	}
	for state, want := range cases {
		if got := state.String(); got != want {
			t.Fatalf("State(%d).String() = %q, want %q", state, got, want)
		}
	}
}

func TestClassifyDialError(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		ctxErr error
		want   State
	}{
		{name: "success", err: nil, want: StateOpen},
		{name: "timeout", err: timeoutErr{}, want: StateTimeout},
		{name: "deadline", err: os.ErrDeadlineExceeded, want: StateTimeout},
		{name: "context canceled", err: context.Canceled, want: StateCanceled},
		{name: "context deadline", err: context.DeadlineExceeded, want: StateCanceled},
		{name: "canceled context wins", err: errors.New("boom"), ctxErr: context.Canceled, want: StateCanceled},
		{name: "wrapped timeout", err: errors.Join(errors.New("dial"), timeoutErr{}), want: StateTimeout},
		{name: "unknown", err: errors.New("boom"), want: StateError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyDialError(tc.err, tc.ctxErr); got != tc.want {
				t.Fatalf("classifyDialError() = %v, want %v", got, tc.want)
			}
		})
	}
}

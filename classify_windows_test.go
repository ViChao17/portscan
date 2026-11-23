//go:build windows

package portscan

import (
	"net"
	"os"
	"syscall"
	"testing"
)

func TestClassifyWindowsErrno(t *testing.T) {
	cases := []struct {
		name string
		code syscall.Errno
		want State
	}{
		{name: "connection refused", code: 10061, want: StateClosed},
		{name: "host unreachable", code: 10065, want: StateUnreachable},
		{name: "network unreachable", code: 10051, want: StateUnreachable},
		{name: "host down", code: 10064, want: StateUnreachable},
		{name: "network down", code: 10050, want: StateUnreachable},
		{name: "other errno", code: 10013, want: StateError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", tc.code)}
			if got := classifyDialError(err, nil); got != tc.want {
				t.Fatalf("classifyDialError(%v) = %v, want %v", err, got, tc.want)
			}
		})
	}
}

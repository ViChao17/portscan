//go:build unix

package portscan

import (
	"net"
	"os"
	"syscall"
	"testing"
)

func TestClassifyUnixErrno(t *testing.T) {
	cases := []struct {
		name string
		code syscall.Errno
		want State
	}{
		{name: "connection refused", code: syscall.ECONNREFUSED, want: StateClosed},
		{name: "host unreachable", code: syscall.EHOSTUNREACH, want: StateUnreachable},
		{name: "network unreachable", code: syscall.ENETUNREACH, want: StateUnreachable},
		{name: "other errno", code: syscall.EACCES, want: StateError},
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

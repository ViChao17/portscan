//go:build windows

package portscan

import (
	"errors"
	"syscall"
)

// Winsock error codes delivered by net.Dial on Windows.
const (
	wsaECONNREFUSED syscall.Errno = 10061
	wsaENETDOWN     syscall.Errno = 10050
	wsaENETUNREACH  syscall.Errno = 10051
	wsaEHOSTDOWN    syscall.Errno = 10064
	wsaEHOSTUNREACH syscall.Errno = 10065
)

func isConnRefused(err error) bool {
	return matchesErrno(err, wsaECONNREFUSED)
}

func isUnreachable(err error) bool {
	return matchesErrno(err, wsaENETDOWN, wsaENETUNREACH, wsaEHOSTDOWN, wsaEHOSTUNREACH)
}

func matchesErrno(err error, codes ...syscall.Errno) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	for _, code := range codes {
		if errno == code {
			return true
		}
	}
	return false
}

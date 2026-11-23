package portscan

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Resolver resolves a host name to IP addresses. *net.Resolver implements it.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// dialFunc performs a single TCP connection attempt.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// config holds the intermediate option state used by New.
type config struct {
	concurrency    int
	connectTimeout time.Duration
	resolver       Resolver
	dial           dialFunc
}

// Option configures a Scanner. Options are applied by New in order.
type Option func(*config) error

// WithConcurrency sets the maximum number of TCP connect attempts that may run
// at the same time. The value must be at least 1. The default is 100.
func WithConcurrency(n int) Option {
	return func(c *config) error {
		if n < 1 {
			return fmt.Errorf("%w: %d", ErrInvalidConcurrency, n)
		}
		c.concurrency = n
		return nil
	}
}

// WithConnectTimeout sets the timeout of a single TCP connect attempt. The
// value must be positive. The default is one second.
func WithConnectTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("%w: %s", ErrInvalidTimeout, d)
		}
		c.connectTimeout = d
		return nil
	}
}

// WithResolver replaces the DNS resolver used for non-IP hosts. A nil resolver
// is rejected. The default is net.DefaultResolver.
func WithResolver(r Resolver) Option {
	return func(c *config) error {
		if r == nil {
			return ErrInvalidResolver
		}
		c.resolver = r
		return nil
	}
}

// withDialer replaces the connect function. It is unexported on purpose: it
// exists so that tests can simulate network behaviour deterministically.
func withDialer(d dialFunc) Option {
	return func(c *config) error {
		c.dial = d
		return nil
	}
}

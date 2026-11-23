package portscan

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestNormalizeHostsDeduplicates(t *testing.T) {
	inputs, err := normalizeHosts([]string{
		"127.0.0.1",
		" 127.0.0.1 ",
		"::1",
		"[::1]",
		"Example.COM",
		"example.com.",
		"example.com",
	})
	if err != nil {
		t.Fatalf("normalizeHosts() error = %v", err)
	}
	if got, want := len(inputs), 3; got != want {
		t.Fatalf("len(inputs) = %d, want %d: %+v", got, want, inputs)
	}
	if inputs[0].ip == nil || !inputs[0].ip.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("first input = %+v, want an IPv4 literal", inputs[0])
	}
	if inputs[1].ip == nil || !inputs[1].ip.Equal(net.ParseIP("::1")) {
		t.Fatalf("second input = %+v, want an IPv6 literal", inputs[1])
	}
	if inputs[2].ip != nil || inputs[2].host != "Example.COM" {
		t.Fatalf("third input = %+v, want the DNS name Example.COM", inputs[2])
	}
}

func TestNormalizeHostsInvalid(t *testing.T) {
	cases := []struct {
		name string
		host string
	}{
		{name: "empty", host: ""},
		{name: "blank", host: "   "},
		{name: "bad ipv4", host: "999.1.1.1"},
		{name: "too many octets", host: "1.2.3.4.5"},
		{name: "bad ipv6", host: "::gg"},
		{name: "bracketed bad ipv6", host: "[::gg]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inputs, err := normalizeHosts([]string{tc.host})
			if err != nil {
				t.Fatalf("normalizeHosts() error = %v, want nil", err)
			}
			if len(inputs) != 1 {
				t.Fatalf("len(inputs) = %d, want 1", len(inputs))
			}
			if !errors.Is(inputs[0].err, ErrInvalidHost) {
				t.Fatalf("input error = %v, want ErrInvalidHost", inputs[0].err)
			}
		})
	}
}

func TestNormalizeHostsEmptyList(t *testing.T) {
	if _, err := normalizeHosts(nil); !errors.Is(err, ErrNoHosts) {
		t.Fatalf("normalizeHosts(nil) error = %v, want ErrNoHosts", err)
	}
	if _, err := normalizeHosts([]string{}); !errors.Is(err, ErrNoHosts) {
		t.Fatalf("normalizeHosts([]) error = %v, want ErrNoHosts", err)
	}
}

func TestDNSCaseIsPreserved(t *testing.T) {
	inputs, err := normalizeHosts([]string{"MiXeD.test"})
	if err != nil {
		t.Fatalf("normalizeHosts() error = %v", err)
	}
	if got := inputs[0].host; got != "MiXeD.test" {
		t.Fatalf("host = %q, want %q", got, "MiXeD.test")
	}
}

func TestResolveTargetsMultipleAddresses(t *testing.T) {
	resolver := newFakeResolver()
	resolver.set("multi.test", "127.0.0.1", "127.0.0.2", "127.0.0.1")

	scanner := mustNew(t, WithResolver(resolver))
	targets, err := scanner.resolveTargets(context.Background(), []string{"multi.test"})
	if err != nil {
		t.Fatalf("resolveTargets() error = %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].err != nil {
		t.Fatalf("target error = %v, want nil", targets[0].err)
	}
	if got, want := len(targets[0].ips), 2; got != want {
		t.Fatalf("len(ips) = %d, want %d (duplicates must be collapsed)", got, want)
	}
}

func TestResolveTargetsFailureIsPerHost(t *testing.T) {
	resolver := newFakeResolver()
	resolver.setErr("bad.test", &net.DNSError{Err: "no such host", Name: "bad.test", IsNotFound: true})
	resolver.set("good.test", "127.0.0.1")

	scanner := mustNew(t, WithResolver(resolver))
	targets, err := scanner.resolveTargets(context.Background(), []string{"bad.test", "good.test"})
	if err != nil {
		t.Fatalf("resolveTargets() error = %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("len(targets) = %d, want 2", len(targets))
	}

	if !errors.Is(targets[0].err, ErrResolveFailed) {
		t.Fatalf("bad target error = %v, want ErrResolveFailed", targets[0].err)
	}
	var resolveErr *ResolveError
	if !errors.As(targets[0].err, &resolveErr) {
		t.Fatalf("bad target error type = %T, want *ResolveError", targets[0].err)
	}
	if resolveErr.Host != "bad.test" {
		t.Fatalf("ResolveError.Host = %q, want %q", resolveErr.Host, "bad.test")
	}
	if targets[1].err != nil || len(targets[1].ips) != 1 {
		t.Fatalf("good target = %+v, want one resolved IP", targets[1])
	}
}

func TestResolveTargetsEmptyDNSAnswer(t *testing.T) {
	resolver := newFakeResolver() // no addresses and no error configured
	scanner := mustNew(t, WithResolver(resolver))

	targets, err := scanner.resolveTargets(context.Background(), []string{"empty.test"})
	if err != nil {
		t.Fatalf("resolveTargets() error = %v", err)
	}
	if !errors.Is(targets[0].err, ErrResolveFailed) {
		t.Fatalf("target error = %v, want ErrResolveFailed", targets[0].err)
	}
}

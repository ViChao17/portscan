package portscan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
)

// hostTarget is a host prepared for scanning: either a set of resolved IP
// addresses or a per-host failure that is reported for every requested port.
type hostTarget struct {
	host string
	ips  []net.IP
	err  error
}

// hostInput is a host after normalization, before DNS resolution.
type hostInput struct {
	host string
	ip   net.IP
	err  error
}

// resolveTargets normalizes the host list and resolves every DNS name. DNS
// lookups are performed once per unique name with at most concurrency
// parallel lookups. Resolution failures do not abort the scan: they are stored
// on the target and later reported per port.
func (s *Scanner) resolveTargets(ctx context.Context, hosts []string) ([]hostTarget, error) {
	inputs, err := normalizeHosts(hosts)
	if err != nil {
		return nil, err
	}

	targets := make([]hostTarget, len(inputs))
	sem := make(chan struct{}, min(len(inputs), s.concurrency))

	var wg sync.WaitGroup
	for i, in := range inputs {
		switch {
		case in.err != nil:
			targets[i] = hostTarget{host: in.host, err: in.err}
		case in.ip != nil:
			targets[i] = hostTarget{host: in.host, ips: []net.IP{in.ip}}
		default:
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				targets[i] = s.resolveOne(ctx, in.host)
			}()
		}
	}
	wg.Wait()

	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	return targets, nil
}

func (s *Scanner) resolveOne(ctx context.Context, host string) hostTarget {
	addrs, err := s.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return hostTarget{host: host, err: &ResolveError{
			Host: host,
			Err:  fmt.Errorf("%w: %w", ErrResolveFailed, err),
		}}
	}

	ips := make([]net.IP, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, addr := range addrs {
		ip := normalizeIP(addr.IP)
		if ip == nil {
			continue
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return hostTarget{host: host, err: &ResolveError{
			Host: host,
			Err:  fmt.Errorf("%w: no IP addresses returned", ErrResolveFailed),
		}}
	}
	return hostTarget{host: host, ips: ips}
}

// normalizeHosts trims, validates and deduplicates the host list while
// preserving the caller's order. The returned error is ErrNoHosts only when
// the list itself is empty; individual bad hosts become hostInput.err values so
// that the rest of the scan can proceed.
func normalizeHosts(hosts []string) ([]hostInput, error) {
	if len(hosts) == 0 {
		return nil, ErrNoHosts
	}

	inputs := make([]hostInput, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))

	for _, raw := range hosts {
		host := strings.TrimSpace(raw)
		if host == "" {
			if _, ok := seen["invalid:empty"]; ok {
				continue
			}
			seen["invalid:empty"] = struct{}{}
			inputs = append(inputs, hostInput{host: "", err: fmt.Errorf("%w: empty host", ErrInvalidHost)})
			continue
		}

		if ip := parseIPLiteral(host); ip != nil {
			key := "ip:" + ip.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			inputs = append(inputs, hostInput{host: host, ip: ip})
			continue
		}

		if looksLikeIPLiteral(host) {
			key := "invalid:" + strings.ToLower(host)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			inputs = append(inputs, hostInput{
				host: host,
				err:  fmt.Errorf("%w: %q is not a valid IP address", ErrInvalidHost, host),
			})
			continue
		}

		key := "dns:" + strings.ToLower(strings.TrimSuffix(host, "."))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		inputs = append(inputs, hostInput{host: host})
	}

	if len(inputs) == 0 {
		return nil, ErrNoHosts
	}
	return inputs, nil
}

// parseIPLiteral parses an IPv4 or IPv6 address, also accepting a bracketed
// IPv6 form such as "[::1]". It returns nil when host is not an IP literal.
func parseIPLiteral(host string) net.IP {
	candidate := host
	if len(candidate) >= 2 && candidate[0] == '[' && candidate[len(candidate)-1] == ']' {
		candidate = candidate[1 : len(candidate)-1]
	}
	return normalizeIP(net.ParseIP(candidate))
}

// looksLikeIPLiteral reports whether host was clearly meant to be an IP
// address. Such hosts are rejected instead of being sent to a DNS resolver.
func looksLikeIPLiteral(host string) bool {
	if strings.HasPrefix(host, "[") || strings.Contains(host, ":") {
		return true
	}
	for _, r := range host {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return strings.Contains(host, ".")
}

func normalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

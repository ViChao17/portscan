package portscan

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// PortSet is an immutable, deduplicated, ascending set of TCP destination
// ports. The zero value is a valid empty set.
//
// A PortSet remembers invalid input (port 0, a reversed range, malformed
// specification) so that it can be used inline, as in portscan.Range(1, 1000);
// Scan and ScanAll report the remembered error before any network activity.
type PortSet struct {
	ports []uint16
	err   error
}

// Ports returns a PortSet containing the given ports. Duplicate ports are
// collapsed. Port 0 is invalid and is reported by Scan/ScanAll as ErrInvalidPort.
func Ports(ports ...uint16) PortSet {
	set := make([]uint16, 0, len(ports))
	var errs []error
	for _, p := range ports {
		if p == 0 {
			errs = append(errs, fmt.Errorf("%w: 0 is not a valid destination port", ErrInvalidPort))
			continue
		}
		set = append(set, p)
	}
	return PortSet{ports: normalizePorts(set), err: errors.Join(errs...)}
}

// Range returns a PortSet containing every port from "from" to "to" inclusive.
//
// Range(from, to) reports ErrInvalidPort if either bound is 0 and
// ErrInvalidRange if from > to.
func Range(from, to uint16) PortSet {
	if from == 0 || to == 0 {
		return PortSet{err: fmt.Errorf("%w: range %d-%d contains port 0", ErrInvalidPort, from, to)}
	}
	if from > to {
		return PortSet{err: fmt.Errorf("%w: %d-%d", ErrInvalidRange, from, to)}
	}
	ports := make([]uint16, 0, int(to)-int(from)+1)
	for p := int(from); p <= int(to); p++ {
		ports = append(ports, uint16(p))
	}
	return PortSet{ports: ports}
}

// ParsePorts parses a comma-separated list of single ports and inclusive
// ranges, for example "80,443,1000-2000". Whitespace around elements is
// ignored. Duplicates and overlapping ranges are collapsed.
//
// Parsed values must be in the range 1-65535. Malformed input is reported as
// ErrInvalidPortSet, port 0 as ErrInvalidPort and a reversed range as
// ErrInvalidRange.
func ParsePorts(spec string) (PortSet, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return PortSet{}, fmt.Errorf("%w: empty specification", ErrInvalidPortSet)
	}

	var ports []uint16
	for _, element := range strings.Split(spec, ",") {
		element = strings.TrimSpace(element)
		if element == "" {
			return PortSet{}, fmt.Errorf("%w: empty element in %q", ErrInvalidPortSet, spec)
		}

		lo, hi, isRange := strings.Cut(element, "-")
		if !isRange {
			port, err := parsePort(element)
			if err != nil {
				return PortSet{}, err
			}
			ports = append(ports, port)
			continue
		}

		from, err := parsePort(strings.TrimSpace(lo))
		if err != nil {
			return PortSet{}, err
		}
		to, err := parsePort(strings.TrimSpace(hi))
		if err != nil {
			return PortSet{}, err
		}
		if from > to {
			return PortSet{}, fmt.Errorf("%w: %d-%d", ErrInvalidRange, from, to)
		}
		for p := int(from); p <= int(to); p++ {
			ports = append(ports, uint16(p))
		}
	}

	return PortSet{ports: normalizePorts(ports)}, nil
}

// Union returns a new PortSet containing the ports of both sets. Neither
// receiver nor argument is modified. Remembered input errors are carried over.
func (p PortSet) Union(other PortSet) PortSet {
	combined := make([]uint16, 0, len(p.ports)+len(other.ports))
	combined = append(combined, p.ports...)
	combined = append(combined, other.ports...)
	return PortSet{
		ports: normalizePorts(combined),
		err:   errors.Join(p.err, other.err),
	}
}

// Ports returns a copy of the ports in ascending order. The caller may modify
// the returned slice.
func (p PortSet) Ports() []uint16 {
	return slices.Clone(p.ports)
}

// Len reports the number of ports in the set.
func (p PortSet) Len() int { return len(p.ports) }

// String returns a compact human-readable form, for example "80,443,1000-2000".
// The empty set is rendered as an empty string.
func (p PortSet) String() string {
	if len(p.ports) == 0 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(p.ports); {
		j := i
		for j+1 < len(p.ports) && p.ports[j+1] == p.ports[j]+1 {
			j++
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		if i == j {
			b.WriteString(strconv.Itoa(int(p.ports[i])))
		} else {
			b.WriteString(strconv.Itoa(int(p.ports[i])))
			b.WriteByte('-')
			b.WriteString(strconv.Itoa(int(p.ports[j])))
		}
		i = j + 1
	}
	return b.String()
}

// validate checks that the set can be scanned.
func (p PortSet) validate() error {
	if p.err != nil {
		return p.err
	}
	if len(p.ports) == 0 {
		return ErrNoPorts
	}
	return nil
}

func parsePort(value string) (uint16, error) {
	if value == "" {
		return 0, fmt.Errorf("%w: empty port", ErrInvalidPortSet)
	}
	n, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: %q", ErrInvalidPortSet, value)
	}
	if n == 0 {
		return 0, fmt.Errorf("%w: 0 is not a valid destination port", ErrInvalidPort)
	}
	if n > 65535 {
		return 0, fmt.Errorf("%w: %q is greater than 65535", ErrInvalidPort, value)
	}
	return uint16(n), nil
}

// normalizePorts returns a sorted, deduplicated copy of ports.
func normalizePorts(ports []uint16) []uint16 {
	if len(ports) == 0 {
		return nil
	}
	slices.Sort(ports)
	return slices.Compact(ports)
}

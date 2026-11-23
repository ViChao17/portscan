package portscan

import (
	"errors"
	"slices"
	"testing"
)

func TestPortsNormalizesAndDeduplicates(t *testing.T) {
	set := Ports(443, 80, 443, 22, 80)

	want := []uint16{22, 80, 443}
	if got := set.Ports(); !slices.Equal(got, want) {
		t.Fatalf("Ports() = %v, want %v", got, want)
	}
	if set.Len() != len(want) {
		t.Fatalf("Len() = %d, want %d", set.Len(), len(want))
	}
	if err := set.validate(); err != nil {
		t.Fatalf("validate() = %v, want nil", err)
	}
}

func TestPortsRejectsZero(t *testing.T) {
	set := Ports(80, 0, 443)
	if err := set.validate(); !errors.Is(err, ErrInvalidPort) {
		t.Fatalf("validate() = %v, want ErrInvalidPort", err)
	}
	if got, want := set.Len(), 2; got != want {
		t.Fatalf("Len() = %d, want %d", got, want)
	}
}

func TestRange(t *testing.T) {
	set := Range(2, 5)
	want := []uint16{2, 3, 4, 5}
	if got := set.Ports(); !slices.Equal(got, want) {
		t.Fatalf("Range(2, 5) = %v, want %v", got, want)
	}

	if got := Range(7, 7); got.Len() != 1 || got.Ports()[0] != 7 {
		t.Fatalf("Range(7, 7) = %v, want a single port 7", got.Ports())
	}

	if err := Range(1000, 1).validate(); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("reversed range error = %v, want ErrInvalidRange", err)
	}
	if err := Range(0, 10).validate(); !errors.Is(err, ErrInvalidPort) {
		t.Fatalf("range from 0 error = %v, want ErrInvalidPort", err)
	}
	if err := Range(10, 0).validate(); !errors.Is(err, ErrInvalidPort) {
		t.Fatalf("range to 0 error = %v, want ErrInvalidPort", err)
	}
}

func TestUnionIsImmutable(t *testing.T) {
	first := Ports(80, 443)
	second := Range(1000, 1002)

	combined := first.Union(second)

	if got, want := combined.Ports(), []uint16{80, 443, 1000, 1001, 1002}; !slices.Equal(got, want) {
		t.Fatalf("Union() = %v, want %v", got, want)
	}
	if got, want := first.Ports(), []uint16{80, 443}; !slices.Equal(got, want) {
		t.Fatalf("receiver mutated: %v, want %v", got, want)
	}
	if got, want := second.Len(), 3; got != want {
		t.Fatalf("argument mutated: len = %d, want %d", got, want)
	}
}

func TestUnionCarriesErrors(t *testing.T) {
	combined := Ports(0).Union(Ports(80))
	if err := combined.validate(); !errors.Is(err, ErrInvalidPort) {
		t.Fatalf("validate() = %v, want ErrInvalidPort", err)
	}
	if got, want := combined.Len(), 1; got != want {
		t.Fatalf("Len() = %d, want %d", got, want)
	}
}

func TestPortSetString(t *testing.T) {
	cases := []struct {
		name string
		set  PortSet
		want string
	}{
		{"empty", PortSet{}, ""},
		{"single", Ports(80), "80"},
		{"ranges", Ports(80, 81, 82, 443, 1000, 999), "80-82,443,999-1000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.set.String(); got != tc.want {
				t.Fatalf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPortsReturnsCopy(t *testing.T) {
	set := Ports(80, 443)
	ports := set.Ports()
	ports[0] = 1

	if got := set.Ports()[0]; got != 80 {
		t.Fatalf("PortSet was mutated through Ports(): got %d, want 80", got)
	}
}

func TestParsePorts(t *testing.T) {
	cases := []struct {
		name    string
		spec    string
		want    []uint16
		wantErr error
	}{
		{name: "single", spec: "80", want: []uint16{80}},
		{name: "list", spec: "443, 80, 22", want: []uint16{22, 80, 443}},
		{name: "range", spec: "1000-1002", want: []uint16{1000, 1001, 1002}},
		{name: "mixed and overlapping", spec: "80, 79-81, 443-443", want: []uint16{79, 80, 81, 443}},
		{name: "whitespace", spec: "  22 , 80-81  ", want: []uint16{22, 80, 81}},
		{name: "empty", spec: "", wantErr: ErrInvalidPortSet},
		{name: "blank", spec: "   ", wantErr: ErrInvalidPortSet},
		{name: "empty element", spec: "80,,443", wantErr: ErrInvalidPortSet},
		{name: "text", spec: "http", wantErr: ErrInvalidPortSet},
		{name: "too large", spec: "65536", wantErr: ErrInvalidPort},
		{name: "range too large", spec: "65535-70000", wantErr: ErrInvalidPort},
		{name: "zero", spec: "0", wantErr: ErrInvalidPort},
		{name: "zero in range", spec: "0-10", wantErr: ErrInvalidPort},
		{name: "reversed", spec: "1000-1", wantErr: ErrInvalidRange},
		{name: "missing end", spec: "1000-", wantErr: ErrInvalidPortSet},
		{name: "missing start", spec: "-1000", wantErr: ErrInvalidPortSet},
		{name: "negative", spec: "-1", wantErr: ErrInvalidPortSet},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set, err := ParsePorts(tc.spec)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ParsePorts(%q) error = %v, want %v", tc.spec, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePorts(%q) error = %v, want nil", tc.spec, err)
			}
			if got := set.Ports(); !slices.Equal(got, tc.want) {
				t.Fatalf("ParsePorts(%q) = %v, want %v", tc.spec, got, tc.want)
			}
		})
	}
}

func TestEmptyPortSetIsInvalid(t *testing.T) {
	var set PortSet
	if err := set.validate(); !errors.Is(err, ErrNoPorts) {
		t.Fatalf("validate() = %v, want ErrNoPorts", err)
	}
}

package traffic_test

import (
	"errors"
	"testing"

	"github.com/gatework/firemon/traffic"
)

func TestParseAddressSet(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
	}{
		{"host", "10.0.0.1", "10.0.0.1"},
		{"prefix is masked", "10.0.0.9/24", "10.0.0.0/24"},
		{"range not aligned", "10.0.0.1-10.0.0.9", "10.0.0.1-10.0.0.9"},
		{"adjacent merge", "10.0.0.0/25, 10.0.0.128/25", "10.0.0.0/24"},
		{"any", "any", "any"},
		{"ipv6", "2406:e300::/32", "2406:e300::/32"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, err := traffic.ParseAddressSet(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if got := s.String(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseAddressSet_Rejects(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"", "10.0.0.256", "10.0.0.1/33", "10.0.0.9-10.0.0.1", "host"} {
		if _, err := traffic.ParseAddressSet(in); !errors.Is(err, traffic.ErrInvalidAddress) {
			t.Errorf("%q: got %v, want ErrInvalidAddress", in, err)
		}
	}
}

func TestAddressSet_Relation(t *testing.T) {
	t.Parallel()
	parse := func(s string) traffic.AddressSet {
		a, err := traffic.ParseAddressSet(s)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	tests := []struct {
		a, b string
		want traffic.Relation
	}{
		{"10.0.0.0/24", "10.0.0.0/24", traffic.RelationEqual},
		{"10.0.0.0/16", "10.0.1.0/24", traffic.RelationSuperset},
		{"10.0.1.0/24", "10.0.0.0/16", traffic.RelationSubset},
		{"10.0.0.0/24", "10.0.0.128-10.0.1.5", traffic.RelationOverlap},
		{"10.0.0.0/24", "10.0.1.0/24", traffic.RelationDisjoint},
	}
	for _, tt := range tests {
		if got := parse(tt.a).Relation(parse(tt.b)); got != tt.want {
			t.Errorf("%s vs %s: got %s, want %s", tt.a, tt.b, got, tt.want)
		}
	}
}

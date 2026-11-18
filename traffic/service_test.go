package traffic_test

import (
	"errors"
	"testing"

	"github.com/gatework/firemon/traffic"
)

func TestParseServiceSet_RoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
	}{
		{"single port", "tcp/80", "tcp/80"},
		{"merge adjacent", "tcp/80,tcp/81-90", "tcp/80-90"},
		{"protocol", "udp", "udp"},
		{"source port", "tcp/0-65535<-443", "tcp/any<-443"},
		{"icmp type", "icmp/8", "icmp/8"},
		{"icmp type and code", "icmp/3/4", "icmp/3/4"},
		{"protocol number", "89", "89"},
		{"any", "any", "any"},
		{"protocol range", "ip/0-5", "ip/0-5"},
		{"sorted by protocol", "udp/53,tcp/53", "tcp/53,udp/53"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, err := traffic.ParseServiceSet(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if got := s.String(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			again, err := traffic.ParseServiceSet(s.String())
			if err != nil || !again.Equal(s) {
				t.Fatalf("round trip of %q: %v %s", s, err, again)
			}
		})
	}
}

func TestParseServiceSet_Rejects(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"", "tcp/70000", "tcp/90-80", "foo", "89/1", "icmp/300"} {
		if _, err := traffic.ParseServiceSet(in); !errors.Is(err, traffic.ErrInvalidService) {
			t.Errorf("%q: got %v, want ErrInvalidService", in, err)
		}
	}
}

func TestServiceSet_Subtract(t *testing.T) {
	t.Parallel()
	web, _ := traffic.ParseServiceSet("tcp/80,tcp/443")
	rest := traffic.AnyService().Subtract(web)
	if rest.Overlaps(web) || !rest.Union(web).IsAny() {
		t.Fatalf("subtract broke the partition: %s", rest)
	}
	if got := traffic.ProtocolService(traffic.ProtocolTCP).Subtract(web).String(); got != "tcp/0-79,tcp/81-442,tcp/444-65535" {
		t.Fatalf("got %q", got)
	}
}

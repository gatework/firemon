package report

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/gatework/firemon/traffic"
)

// A thousand scattered pieces read as their box and count, never as a
// megabyte line.
func TestBoundedText_ManyPieces(t *testing.T) {
	t.Parallel()
	var spaces []traffic.Space
	for i := range 1000 {
		a := netip.AddrFrom4([4]byte{10, byte(i / 250), byte(i % 250), 1})
		spaces = append(spaces, traffic.Space{
			Src:     traffic.NewAddressSet(netip.PrefixFrom(a, 32)),
			Dst:     traffic.AnyIPv4(),
			Service: traffic.PortService(traffic.ProtocolTCP, traffic.Port(uint16(1000+i*2))),
		})
	}
	got := boundedText(spaces)
	if len(got) > maxTrafficText+80 || !strings.HasPrefix(got, "part of ") || !strings.Contains(got, "(1000 pieces)") {
		t.Fatalf("%d bytes: %.200s", len(got), got)
	}
	if one := boundedText(spaces[:1]); strings.HasPrefix(one, "part of") {
		t.Fatalf("one piece is written as it is: %s", one)
	}
}

func TestFoldApps(t *testing.T) {
	t.Parallel()
	got := foldApps([]string{"Commvault", "SSH", "COMMVAULT", "ssh-putty"})
	if strings.Join(got, ",") != "Commvault,SSH,ssh-putty" {
		t.Fatalf("%v", got)
	}
}

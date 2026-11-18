package cli

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/spf13/pflag"

	"github.com/gatework/firemon/design"
)

// natFlags ask for a NAT translation with the access.
type natFlags struct {
	mode, address, iface string
	port                 uint16
}

func (n *natFlags) register(f *pflag.FlagSet) {
	f.StringVar(&n.mode, "nat", "", "also design NAT: snat (source, PAT), dnat (publish a server port), static (one-to-one)")
	f.StringVar(&n.address, "nat-ip", "", "public address: the translated source, or the published address of the server")
	f.Uint16Var(&n.port, "nat-port", 0, "published port of dnat (default: the service port)")
	f.StringVar(&n.iface, "egress", "", "egress interface of snat (default: from routing)")
}

// intent returns the NAT part of an intent; nil when none is asked.
func (n *natFlags) intent() (*design.NATIntent, error) {
	if n.mode == "" {
		if n.address != "" || n.port != 0 || n.iface != "" {
			return nil, errors.New("--nat-ip, --nat-port and --egress need --nat")
		}
		return nil, nil //nolint:nilnil // no NAT asked
	}
	in := &design.NATIntent{Port: n.port, Interface: n.iface}
	switch strings.ToLower(n.mode) {
	case "snat", "source":
		in.Mode = design.NATModeSource
	case "dnat", "destination":
		in.Mode = design.NATModeDestination
	case "static", "bnat":
		in.Mode = design.NATModeStatic
	default:
		return nil, fmt.Errorf("--nat %q: use snat, dnat or static", n.mode)
	}
	if n.address != "" {
		a, err := netip.ParseAddr(strings.TrimSpace(n.address))
		if err != nil {
			return nil, fmt.Errorf("--nat-ip: %w", err)
		}
		in.Address = a.Unmap()
	}
	if n.port != 0 && in.Mode != design.NATModeDestination {
		return nil, errors.New("--nat-port applies to dnat")
	}
	return in, nil
}

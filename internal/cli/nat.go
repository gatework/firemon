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
	f.StringVar(&n.mode, "nat", "", "同时设计 NAT：snat（源地址转换，PAT）、dnat（发布服务器端口）、static（一对一）")
	f.StringVar(&n.address, "nat-ip", "", "公网地址：snat 的转换后源地址，或 dnat/static 发布的服务器地址")
	f.Uint16Var(&n.port, "nat-port", 0, "dnat 发布的端口（默认与服务端口相同）")
	f.StringVar(&n.iface, "egress", "", "snat 的出接口（默认按路由确定）")
}

// intent returns the NAT part of an intent; nil when none is asked.
func (n *natFlags) intent() (*design.NATIntent, error) {
	if n.mode == "" {
		if n.address != "" || n.port != 0 || n.iface != "" {
			return nil, errors.New("--nat-ip、--nat-port、--egress 需要配合 --nat 使用")
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
		return nil, fmt.Errorf("--nat %q：可选 snat、dnat 或 static", n.mode)
	}
	if n.address != "" {
		a, err := netip.ParseAddr(strings.TrimSpace(n.address))
		if err != nil {
			return nil, fmt.Errorf("--nat-ip: %w", err)
		}
		in.Address = a.Unmap()
	}
	if n.port != 0 && in.Mode != design.NATModeDestination {
		return nil, errors.New("--nat-port 只用于 dnat")
	}
	return in, nil
}

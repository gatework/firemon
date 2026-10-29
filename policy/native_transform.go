package policy

import (
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

func stoneStaticTransform(n *natTransform, r fm.StaticNATRecord) {
	if !r.Bidirectional {
		n.egress = r.Interface
	}
}
func stoneDynamicTransform(n *natTransform) { n.egress = n.dynamic.Record().Interface }
func stoneReverseStatic(n natTransform, r fm.StaticNATRecord) natTransform {
	// StoneOS BNAT is unconditional one-to-one source mapping, with an implicit
	// inverse destination mapping. Extra selectors have no established inverse.
	n.known = n.known && r.Bidirectional && len(r.Source) > 0 && len(r.Destination) == 0 &&
		len(r.SourcePorts) == 0 && len(r.DestinationPorts) == 0 && r.Interface == "" &&
		r.Match.AnyDestination && r.Match.AnyService && r.Match.AnyFromZone && r.Match.AnyToZone &&
		r.Match.Schedule == "" && len(r.Match.Applications) == 0 && len(r.Match.Users) == 0 && len(r.Match.Unsupported) == 0
	n.match = fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}
	n.source, n.destination, n.sourcePorts, n.destinationPorts = nil, nil, nil, nil
	for _, m := range r.Source {
		if m.Mode != fm.Offset && m.Mode != fm.Identity {
			n.known = false
		}
		n.destination = append(n.destination, fm.Mapping{Original: m.Translated, Translated: m.Original, Mode: m.Mode})
	}
	return n
}
func huaweiTransform(n *natTransform) {
	r := n.dynamic.Record()
	if r.Order.Section == "nat-policy" {
		n.egress = r.Interface
	}
	for _, pool := range []*fm.NATPool{n.dynamic.SourcePool(), n.dynamic.DestinationPool()} {
		if pool != nil {
			n.known = n.known && len(pool.Record().Unsupported) == 0
		}
	}
	if r.SourceMode == fm.InterfaceIP {
		iface := n.dynamic.Interface()
		n.known = n.known && iface != nil
		if iface != nil {
			n.known = n.known && !iface.Disabled() && len(iface.Record().Unsupported) == 0 && len(iface.Record().Addresses) == 1
		}
	}
}
func screenOSTransform(n *natTransform) {
	if n.dynamic.Record().SourceMode != fm.InterfaceIP || len(n.sourcePorts) != 0 {
		return
	}
	// ScreenOS reserves the well-known ports for both DIP and interface PAT.
	// Allocation remains possible, not an exact observed session binding.
	n.sourcePorts = []fm.PortMapping{{Original: flow.Interval{High: 65535}, Translated: flow.Interval{Low: 1024, High: 65535}, Mode: fm.Constant}}
}

package migrate

import (
	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// application returns the target name of a source application: from the
// mapping file (exact), from the built-in table (approximate), or none.
func (tr *translator) application(a string) (target string, approx, ok bool) {
	if t, ok := tr.m.Applications[a]; ok {
		return t, false, true
	}
	if tr.caps.ApplicationAlias == nil {
		return "", false, false
	}
	t, ok := tr.caps.ApplicationAlias(tr.src.Vendor, a)
	return t, true, ok
}

// portlessApplication finds a target signature for a service without ports.
func (tr *translator) portlessApplication(set traffic.ServiceSet) (string, bool) {
	if tr.caps.ServiceApplication == nil {
		return "", false
	}
	return tr.caps.ServiceApplication(set)
}

// applicationPorts returns the default ports of every application, when
// all are known.
func (tr *translator) applicationPorts(apps []string) (traffic.ServiceSet, bool) {
	var out traffic.ServiceSet
	for _, a := range apps {
		ports, ok := tr.fw.ApplicationPorts(a)
		if !ok || ports.IsEmpty() {
			return traffic.ServiceSet{}, false
		}
		out = out.Union(ports)
	}
	return out, true
}

// serviceEntries writes a service set as entries, one per protocol.
func serviceEntries(set traffic.ServiceSet) []firemon.ServiceEntry {
	var entries []firemon.ServiceEntry
	for r := range set.All() {
		for p := int(r.ProtocolLow); p <= int(r.ProtocolHigh); p++ {
			entries = append(entries, firemon.ServiceEntry{Protocol: traffic.Protocol(p), Src: r.Src, Dst: r.Dst})
		}
	}
	return entries
}

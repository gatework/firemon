package paloalto

import (
	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// builtinServices returns the PAN-OS predefined services not overridden by
// the configuration.
func builtinServices(services, groups map[string]int) []firemon.Service {
	tcp := func(p uint16) firemon.ServiceEntry { return firemon.PortEntry(traffic.ProtocolTCP, traffic.Port(p)) }
	all := []firemon.Service{
		{Name: "service-http", Predefined: true, Entries: []firemon.ServiceEntry{tcp(80), tcp(8080)}},
		{Name: "service-https", Predefined: true, Entries: []firemon.ServiceEntry{tcp(443)}},
	}
	var out []firemon.Service
	for _, svc := range all {
		_, isService := services[svc.Name]
		_, isGroup := groups[svc.Name]
		if !isService && !isGroup {
			out = append(out, svc)
		}
	}
	return out
}

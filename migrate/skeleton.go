package migrate

import (
	"github.com/gatework/firemon"
)

// Skeleton returns a mapping to review before translating src: every
// zone, interface and virtual router mapped to itself (the target's
// default router for the source's), every predefined service the rules use
// mapped to the target's predefined service with the same ports when there
// is one, and every application mapped to itself. An operator fills in the
// interface ports and checks the applications.
func Skeleton(src *firemon.Config, t Target) (Mapping, error) {
	fw, err := firemon.Compile(src)
	if err != nil {
		return Mapping{}, err
	}
	m := Mapping{
		Zones: map[string]string{}, Interfaces: map[string]string{}, VirtualRouters: map[string]string{},
		Services: map[string]string{}, Applications: map[string]string{},
	}
	for _, z := range src.Zones {
		m.Zones[z.Name] = z.Name
	}
	for _, i := range src.Interfaces {
		m.Interfaces[i.Name] = i.Name
	}
	for _, vr := range src.VirtualRouters {
		m.VirtualRouters[vr.Name] = vr.Name
		if vr.Name == src.Semantics.DefaultVirtualRouter && t.Semantics.DefaultVirtualRouter != "" {
			m.VirtualRouters[vr.Name] = t.Semantics.DefaultVirtualRouter
		}
	}
	predefined := map[string]bool{}
	for _, s := range src.Services {
		predefined[s.Name] = s.Predefined
	}
	for _, r := range src.Rules {
		for _, s := range r.Services {
			if !predefined[s] {
				continue
			}
			set, ok := fw.Service(s)
			if !ok || set.IsAny() {
				continue
			}
			for _, n := range t.Services.Names() {
				if ts, _ := t.Services.Lookup(n); ts.Equal(set) {
					m.Services[s] = n
					break
				}
			}
		}
		for _, a := range r.Applications() {
			m.Applications[a] = a
		}
	}
	return m, nil
}

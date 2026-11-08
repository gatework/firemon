package policy

import (
	"cmp"
	"context"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// Native pools may encode a constant over every address/port while Match limits
// its actual input to a host and service. Invert that established domain, never
// the broad storage interval. The native packet query still proves each alias.
func (e Engine) aliasGeometry(ctx context.Context, fw *fm.Firewall, n natTransform, remaining *int) (natTransform, error) {
	budget := packetProofBudget{limits: e.Limits.WithDefaults(), remaining: *remaining}
	defer func() { *remaining = budget.remaining }()
	resolver := &resolutionBudget{ctx: ctx, limit: min(budget.remaining, budget.limits.MaxCombinations)}
	for _, axis := range []struct {
		mappings *[]fm.Mapping
		refs     []fm.AddressRef
		any      bool
	}{{&n.source, n.match.Sources, n.match.AnySource}, {&n.destination, n.match.Destinations, n.match.AnyDestination}} {
		if len(*axis.mappings) == 0 || axis.any {
			continue
		}
		addresses, known, err := resolveAddresses(fw, axis.refs, false, resolver)
		if err != nil {
			return natTransform{}, err
		}
		n.known = n.known && known
		if !known {
			continue
		}
		if _, err := budget.product(ctx, len(*axis.mappings), addresses.RangeCount()); err != nil {
			return natTransform{}, err
		}
		var mappings []fm.Mapping
		ranges := addresses.Ranges()
		for _, m := range *axis.mappings {
			for _, address := range ranges {
				original, ok := m.Original.Intersection(address)
				if !ok {
					continue
				}
				translated, err := translate(original, m)
				if err != nil {
					n.known = false
					translated = m.Translated
				}
				mappings = append(mappings, fm.Mapping{Original: original, Translated: translated, Mode: m.Mode})
			}
		}
		*axis.mappings = mappings
	}
	if len(n.sourcePorts)+len(n.destinationPorts) != 0 && !n.match.AnyService {
		terms, known, err := resolveServices(fw, n.match.Services, false, resolver)
		if err != nil {
			return natTransform{}, err
		}
		n.known = n.known && known
		if known {
			for _, axis := range []struct {
				mappings *[]fm.PortMapping
				source   bool
			}{{&n.sourcePorts, true}, {&n.destinationPorts, false}} {
				if len(*axis.mappings) == 0 {
					continue
				}
				ports := make([]flow.Interval, 0, len(terms))
				for _, term := range terms {
					port := term.DestinationPort
					if axis.source {
						port = term.SourcePort
					}
					ports = append(ports, port)
				}
				ports = mergePorts(ports)
				if _, err := budget.product(ctx, len(*axis.mappings), len(ports)); err != nil {
					return natTransform{}, err
				}
				var mappings []fm.PortMapping
				for _, m := range *axis.mappings {
					for _, port := range ports {
						original := flow.Interval{Low: max(m.Original.Low, port.Low), High: min(m.Original.High, port.High)}
						if original.Low > original.High {
							continue
						}
						translated := m.Translated
						if m.Mode == fm.Identity || m.Mode == fm.Offset {
							translated = flow.Interval{Low: m.Translated.Low + (original.Low - m.Original.Low), High: m.Translated.Low + (original.High - m.Original.Low)}
						}
						mappings = append(mappings, fm.PortMapping{Original: original, Translated: translated, Mode: m.Mode})
					}
				}
				*axis.mappings = mappings
			}
		}
	}
	return n, budget.take(ctx, resolver.spent)
}

func mergePorts(ports []flow.Interval) []flow.Interval {
	slices.SortFunc(ports, func(a, b flow.Interval) int { return cmp.Compare(a.Low, b.Low) })
	var out []flow.Interval
	for _, port := range ports {
		if len(out) > 0 && uint32(port.Low) <= uint32(out[len(out)-1].High)+1 {
			out[len(out)-1].High = max(out[len(out)-1].High, port.High)
		} else {
			out = append(out, port)
		}
	}
	return out
}

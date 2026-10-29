// Package analysis implements bounded firewall lifecycle analysis and plans.
package analysis

import (
	"context"
	"errors"

	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

var ErrInvalid = errors.New("invalid lifecycle analysis input")

type RequestGroup struct {
	Request policy.Request
	Inputs  []int
}
type RequestOptimizer struct{ MaxComparisons, MaxRegions int }

// Optimize groups identical contexts while retaining exact paired traffic. Its
// fixed-point coalescing joins traffic regions only across one adjacent/overlapping axis.
func (o RequestOptimizer) Optimize(ctx context.Context, requests []policy.Request) ([]RequestGroup, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(requests) == 0 || len(requests) > 100 {
		return nil, ErrInvalid
	}
	comparisons := o.MaxComparisons
	maxRegions := (policy.Limits{MaxRegions: o.MaxRegions}).WithDefaults().MaxRegions
	if comparisons <= 0 {
		comparisons = 20000
	}
	charge := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if comparisons <= 0 {
			return policy.ErrBudget
		}
		comparisons--
		return nil
	}
	var groups []RequestGroup
	for index, q := range requests {
		if q.Traffic.Empty() {
			return nil, ErrInvalid
		}
		if q.RuleSet == "" {
			q.RuleSet = "security"
		}
		found := false
		for i := range groups {
			if err := charge(); err != nil {
				return nil, err
			}
			if !q.SameContext(groups[i].Request) {
				continue
			}
			merged, err := groups[i].Request.Traffic.Union(q.Traffic, maxRegions)
			if err != nil {
				return nil, err
			}
			groups[i].Request.Traffic = merged
			groups[i].Inputs = append(groups[i].Inputs, index)
			found = true
			break
		}
		if !found {
			groups = append(groups, RequestGroup{Request: q, Inputs: []int{index}})
		}
	}
	for i := range groups {
		regions := groups[i].Request.Traffic.Regions()
		for {
			merged := false
			for a := 0; a < len(regions) && !merged; a++ {
				for b := a + 1; b < len(regions); b++ {
					if err := charge(); err != nil {
						return nil, err
					}
					if region, ok := mergeAdjacentRegions(regions[a], regions[b]); ok {
						regions[a] = region
						regions = append(regions[:b], regions[b+1:]...)
						merged = true
						break
					}
				}
			}
			if !merged {
				break
			}
		}
		var err error
		groups[i].Request.Traffic, err = flow.NewTraffic(maxRegions, regions...)
		if err != nil {
			return nil, err
		}
	}
	return groups, nil
}

func mergeAdjacentRegions(a, b flow.TrafficRegion) (flow.TrafficRegion, bool) {
	out := a
	differences := 0
	for i, pair := range [][2]flow.AddressRange{{a.Source, b.Source}, {a.Destination, b.Destination}} {
		if pair[0] == pair[1] {
			continue
		}
		differences++
		if differences > 1 {
			return flow.TrafficRegion{}, false
		}
		u, err := flow.NewAddressSet(pair[:]...)
		if err != nil || len(u.Ranges()) != 1 {
			return flow.TrafficRegion{}, false
		}
		if i == 0 {
			out.Source = u.Ranges()[0]
		} else {
			out.Destination = u.Ranges()[0]
		}
	}
	for i, pair := range [][2]flow.Interval{{a.Protocol, b.Protocol}, {a.SourcePort, b.SourcePort}, {a.DestinationPort, b.DestinationPort}, {a.ICMPType, b.ICMPType}, {a.ICMPCode, b.ICMPCode}} {
		if pair[0] == pair[1] {
			continue
		}
		differences++
		if differences > 1 || uint32(pair[0].High)+1 < uint32(pair[1].Low) || uint32(pair[1].High)+1 < uint32(pair[0].Low) {
			return flow.TrafficRegion{}, false
		}
		v := flow.Interval{Low: min(pair[0].Low, pair[1].Low), High: max(pair[0].High, pair[1].High)}
		switch i {
		case 0:
			out.Protocol = v
		case 1:
			out.SourcePort = v
		case 2:
			out.DestinationPort = v
		case 3:
			out.ICMPType = v
		case 4:
			out.ICMPCode = v
		}
	}
	return out, out.Valid()
}

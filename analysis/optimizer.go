// Package analysis implements bounded firewall lifecycle analysis and plans.
package analysis

import (
	"context"
	"errors"
	"slices"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

var ErrInvalid = errors.New("invalid lifecycle analysis input")

type RequestGroup struct {
	Request policy.Request
	Inputs  []int
}

// Optimizer bounds declared regions per context and index/comparison work.
// Nonpositive limits use the policy region default and 20000 comparisons.
type Optimizer struct{ MaxComparisons, MaxRegions int }

type requestContext struct {
	scope, ruleSet   string
	from, to, egress fm.ID
	at               time.Time
}

// Optimize retains exact source/destination/service associations and input
// provenance. Each fixed-point pass indexes regions by their other six axes,
// then merges only overlapping or adjacent intervals of the remaining axis.
func (o Optimizer) Optimize(ctx context.Context, requests []policy.Request) ([]RequestGroup, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(requests) == 0 || len(requests) > 100 {
		return nil, ErrInvalid
	}
	remaining := o.MaxComparisons
	if remaining <= 0 {
		remaining = 20000
	}
	maxRegions := (policy.Limits{MaxRegions: o.MaxRegions}).WithDefaults().MaxRegions
	charge := func(count int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if count > remaining {
			return policy.ErrBudget
		}
		remaining -= count
		return nil
	}
	groups := make([]RequestGroup, 0, len(requests))
	declared := make([][]flow.TrafficRegion, 0, len(requests))
	contexts := make(map[requestContext]int, len(requests))
	for index, q := range requests {
		if q.Traffic.Empty() {
			return nil, ErrInvalid
		}
		count := q.Traffic.RegionCount()
		// Check before copying the immutable traffic container.
		if count > maxRegions {
			return nil, flow.ErrBudget
		}
		if err := charge(1 + count); err != nil {
			return nil, err
		}
		if q.RuleSet == "" {
			q.RuleSet = "security"
		}
		key := requestContext{q.Scope, q.RuleSet, q.FromZone, q.ToZone, q.EgressInterface, q.At.Round(0).UTC()}
		group, found := contexts[key]
		if !found {
			group = len(groups)
			contexts[key] = group
			groups = append(groups, RequestGroup{Request: q})
			declared = append(declared, nil)
		}
		if count > maxRegions-len(declared[group]) {
			return nil, flow.ErrBudget
		}
		declared[group] = append(declared[group], q.Traffic.Regions()...)
		groups[group].Inputs = append(groups[group].Inputs, index)
	}
	for index, regions := range declared {
		// Normalize overlaps once, instead of cloning the growing union per input.
		traffic, err := flow.NewTraffic(maxRegions, regions...)
		if err != nil {
			return nil, err
		}
		regions = traffic.Regions()
		for {
			// Each scan has at most 120 pairs; direct comparison avoids seven
			// signature maps for a tiny set, using the same exact union predicate.
			if len(regions) <= 16 {
				regions, err = mergeSmallRegions(regions, charge)
				if err != nil {
					return nil, err
				}
				break
			}
			before := len(regions)
			for axis := range 7 {
				if len(regions) < 2 {
					break
				}
				regions, err = mergeAxis(regions, axis, charge)
				if err != nil {
					return nil, err
				}
			}
			if len(regions) == before {
				break
			}
		}
		var orderErr error
		slices.SortFunc(regions, func(a, b flow.TrafficRegion) int {
			if orderErr == nil {
				orderErr = charge(1)
			}
			if orderErr != nil {
				return 0
			}
			return compareRequestRegion(a, b)
		})
		if orderErr != nil {
			return nil, orderErr
		}
		if err := charge(0); err != nil {
			return nil, err
		}
		groups[index].Request.Traffic, err = flow.NewTraffic(maxRegions, regions...)
		if err != nil {
			return nil, err
		}
	}
	return groups, ctx.Err()
}

func regionIntervals(r *flow.TrafficRegion) [5]*flow.Interval {
	return [5]*flow.Interval{&r.Protocol, &r.SourcePort, &r.DestinationPort, &r.ICMPType, &r.ICMPCode}
}
func regionAddress(r *flow.TrafficRegion, axis int) *flow.AddressRange {
	if axis == 0 {
		return &r.Source
	}
	return &r.Destination
}

type indexedRegion struct {
	region flow.TrafficRegion
	bucket int
}

func mergeAxis(regions []flow.TrafficRegion, axis int, charge func(int) error) ([]flow.TrafficRegion, error) {
	if err := charge(len(regions)); err != nil {
		return nil, err
	}
	// Preserve first-seen bucket order; map iteration never selects output order.
	indexes := make(map[flow.TrafficRegion]int, len(regions))
	indexed := make([]indexedRegion, len(regions))
	for n, r := range regions {
		key := requestRegionSignature(r, axis)
		index, found := indexes[key]
		if !found {
			index = len(indexes)
			indexes[key] = index
		}
		indexed[n] = indexedRegion{region: r, bucket: index}
	}
	var sortErr error
	slices.SortFunc(indexed, func(a, b indexedRegion) int {
		if sortErr == nil {
			sortErr = charge(1)
		}
		if sortErr != nil {
			return 0
		}
		if a.bucket != b.bucket {
			return a.bucket - b.bucket
		}
		if axis < 2 {
			return regionAddress(&a.region, axis).First.Compare(regionAddress(&b.region, axis).First)
		}
		return int(regionIntervals(&a.region)[axis-2].Low) - int(regionIntervals(&b.region)[axis-2].Low)
	})
	if sortErr != nil {
		return nil, sortErr
	}
	out := regions[:0]
	current := indexed[0]
	for _, next := range indexed[1:] {
		if err := charge(1); err != nil {
			return nil, err
		}
		if current.bucket == next.bucket && unionAxis(&current.region, next.region, axis) {
			continue
		}
		out = append(out, current.region)
		current = next
	}
	return append(out, current.region), nil
}

func mergeSmallRegions(regions []flow.TrafficRegion, charge func(int) error) ([]flow.TrafficRegion, error) {
	for {
		changed := false
		for a := 0; a < len(regions) && !changed; a++ {
			for b := a + 1; b < len(regions); b++ {
				if err := charge(1); err != nil {
					return nil, err
				}
				if region, ok := mergeRegionPair(regions[a], regions[b]); ok {
					regions[a] = region
					regions = append(regions[:b], regions[b+1:]...)
					changed = true
					break
				}
			}
		}
		if !changed {
			return regions, nil
		}
	}
}
func mergeRegionPair(a, b flow.TrafficRegion) (flow.TrafficRegion, bool) {
	axis := -1
	if a.Source != b.Source {
		axis = 0
	}
	if a.Destination != b.Destination {
		if axis >= 0 {
			return flow.TrafficRegion{}, false
		}
		axis = 1
	}
	left, right := regionIntervals(&a), regionIntervals(&b)
	for n := range left {
		if *left[n] != *right[n] {
			if axis >= 0 {
				return flow.TrafficRegion{}, false
			}
			axis = n + 2
		}
	}
	if axis < 0 {
		return a, true
	}
	if axis < 2 {
		if regionAddress(&a, axis).First.Compare(regionAddress(&b, axis).First) > 0 {
			a, b = b, a
		}
	} else if regionIntervals(&a)[axis-2].Low > regionIntervals(&b)[axis-2].Low {
		a, b = b, a
	}
	if !unionAxis(&a, b, axis) {
		return flow.TrafficRegion{}, false
	}
	return a, true
}

func requestRegionSignature(r flow.TrafficRegion, axis int) flow.TrafficRegion {
	if axis < 2 {
		*regionAddress(&r, axis) = flow.AddressRange{}
	} else {
		*regionIntervals(&r)[axis-2] = flow.Interval{}
	}
	return r
}

// Other axes are equal by construction, and the selected axis is sorted. This
// exact interval union cannot introduce a source/destination cross product.
func unionAxis(current *flow.TrafficRegion, next flow.TrafficRegion, axis int) bool {
	if axis < 2 {
		a, b := regionAddress(current, axis), regionAddress(&next, axis)
		if a.First.BitLen() != b.First.BitLen() {
			return false
		}
		if a.Last.Compare(b.First) < 0 && a.Last.Next() != b.First {
			return false
		}
		if a.Last.Compare(b.Last) < 0 {
			a.Last = b.Last
		}
		return true
	}
	a, b := regionIntervals(current)[axis-2], regionIntervals(&next)[axis-2]
	if uint32(a.High)+1 < uint32(b.Low) {
		return false
	}
	a.High = max(a.High, b.High)
	return true
}

func compareRequestRegion(a, b flow.TrafficRegion) int {
	for _, pair := range [][2]flow.AddressRange{{a.Source, b.Source}, {a.Destination, b.Destination}} {
		if c := pair[0].First.Compare(pair[1].First); c != 0 {
			return c
		}
		if c := pair[0].Last.Compare(pair[1].Last); c != 0 {
			return c
		}
	}
	left, right := regionIntervals(&a), regionIntervals(&b)
	for n := range left {
		if c := int(left[n].Low) - int(right[n].Low); c != 0 {
			return c
		}
		if c := int(left[n].High) - int(right[n].High); c != 0 {
			return c
		}
	}
	return 0
}

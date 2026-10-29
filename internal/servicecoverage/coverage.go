// Package servicecoverage projects service tuples into the exact traffic algebra.
// Both address dimensions are fixed sentinels, not network match constraints.
// Compare these projections only with other service projections.
package servicecoverage

import (
	"context"
	"net/netip"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

func anchor() flow.AddressRange {
	zero := netip.IPv4Unspecified()
	return flow.AddressRange{First: zero, Last: zero}
}

// FromTerms preserves the union of complete five-dimensional service tuples.
func FromTerms(ctx context.Context, terms []fm.ServiceTerm, limit int) (flow.Traffic, error) {
	if err := ctx.Err(); err != nil {
		return flow.Traffic{}, err
	}
	if limit < 1 || len(terms) > limit {
		return flow.Traffic{}, flow.ErrBudget
	}
	regions := make([]flow.TrafficRegion, 0, len(terms))
	for _, term := range terms {
		if err := ctx.Err(); err != nil {
			return flow.Traffic{}, err
		}
		regions = append(regions, flow.TrafficRegion{
			Source: anchor(), Destination: anchor(),
			Protocol: term.Protocol, SourcePort: term.SourcePort, DestinationPort: term.DestinationPort,
			ICMPType: term.ICMPType, ICMPCode: term.ICMPCode,
		})
	}
	return flow.NewTraffic(limit, regions...)
}

// FromTraffic removes address constraints without combining independent axes.
func FromTraffic(ctx context.Context, traffic flow.Traffic, limit int) (flow.Traffic, error) {
	if err := ctx.Err(); err != nil {
		return flow.Traffic{}, err
	}
	if limit < 1 || traffic.RegionCount() > limit {
		return flow.Traffic{}, flow.ErrBudget
	}
	regions := traffic.Regions()
	for i := range regions {
		if err := ctx.Err(); err != nil {
			return flow.Traffic{}, err
		}
		regions[i].Source, regions[i].Destination = anchor(), anchor()
	}
	return flow.NewTraffic(limit, regions...)
}

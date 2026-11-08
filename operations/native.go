package operations

import (
	"context"
	"slices"

	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

// NativeEffects attaches explicit NAT declarations and original-wire intents to
// one explicit device target. PolicyTraffic supplies an explicit native view
// when different from the business wire traffic; final packet proof checks it.
type NativeEffects struct {
	Lifetime      *plan.ScheduleIntent
	PolicyTraffic flow.Traffic
	Additions     plan.NativeAdditions
	NAT           []policy.NATIntent
}

func cloneNativeEffects(n *NativeEffects) *NativeEffects {
	if n == nil {
		return nil
	}
	copy := plan.NativeRequest{Additions: n.Additions, NAT: n.NAT, Lifetime: n.Lifetime}.Clone()
	return &NativeEffects{PolicyTraffic: n.PolicyTraffic, Additions: copy.Additions, NAT: copy.NAT, Lifetime: copy.Lifetime}
}
func (r *targetBatch) nativeTarget(input int, traffic flow.Traffic, target AccessTarget, q policy.Request, sources []string) (*targetEntry, error) {
	n := r.inputs[input].request.Native
	wire := policy.PacketRequest{Request: q, VRF: target.VRF}
	if !n.PolicyTraffic.Empty() {
		q.Traffic = n.PolicyTraffic
	}
	native := plan.NativeRequest{Request: q, Additions: n.Additions, NAT: n.NAT, Lifetime: n.Lifetime, Sources: slices.Clone(r.inputs[input].request.Sources)}.Clone()
	var proof *targetPacketProof
	if target.Packet {
		native.Packet = &wire
		proof = &targetPacketProof{packet: wire}
	}
	outcome := TargetOutcome{Device: target.Device, Revision: r.manifest.Devices[target.Device].Revision, Wire: traffic, NativeRequests: []policy.Request{q}, Sources: slices.Clone(sources), Disposition: plan.BatchPending}
	entry, err := r.record(input, outcome, "policy")
	if err != nil {
		return nil, err
	}
	r.queue(entry, targetPlanning{request: q, native: &native}, proof)
	return entry, nil
}

// Native business ingress runs before topology cloning and snapshot reads. The
// shallow adapter below owns no copied declaration/member containers; both the
// wrapper and nested native allowance are charged before the first deep copy.
func preflightBusinessNative(ctx context.Context, requests []AccessRequest, limits policy.Limits) error {
	hasNative := false
	for _, r := range requests {
		if err := ctx.Err(); err != nil {
			return err
		}
		hasNative = hasNative || r.Native != nil
	}
	if !hasNative {
		return nil
	}
	limits = limits.WithDefaults()
	remaining := limits.MaxVisits
	take := func(count int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if count < 0 || count > remaining {
			return policy.ErrBudget
		}
		remaining -= count
		return nil
	}
	if err := take(len(requests)); err != nil {
		return err
	}
	native := make([]plan.NativeRequest, 0, len(requests))
	for _, r := range requests {
		for _, count := range []int{r.Traffic.RegionCount(), len(r.Sources), len(r.Targets), len(r.WireCandidates)} {
			if err := take(count); err != nil {
				return err
			}
		}
		for _, target := range r.Targets {
			if err := take(target.Request.Traffic.RegionCount()); err != nil {
				return err
			}
		}
		for _, wire := range r.WireCandidates {
			if err := take(wire.Traffic.RegionCount()); err != nil {
				return err
			}
			if err := take(wire.Target.Request.Traffic.RegionCount()); err != nil {
				return err
			}
		}
		if r.Native != nil {
			native = append(native, plan.NativeRequest{Request: policy.Request{Traffic: r.Native.PolicyTraffic}, Additions: r.Native.Additions, NAT: r.Native.NAT, Lifetime: r.Native.Lifetime})
		}
	}
	// Never pass exhausted capacity as zero: policy.Limits defines zero as default.
	if remaining == 0 {
		return policy.ErrBudget
	}
	limits.MaxVisits = remaining
	return plan.PreflightNativeRequests(ctx, native, limits)
}

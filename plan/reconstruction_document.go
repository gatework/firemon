package plan

import (
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

// These private records preserve version-1 reconstruction bytes. Reports use
// their own adapter and cannot change the interpretation of executable intent.
type reconstructionEffects struct {
	Lifetime      *ScheduleIntent      `json:"lifetime,omitempty"`
	PolicyTraffic []flow.TrafficRegion `json:"policy_traffic,omitempty"`
	Additions     NativeAdditions      `json:"additions"`
	NAT           []reconstructionNAT  `json:"nat"`
}
type reconstructionNAT struct {
	Request reconstructionPolicy `json:"request"`
	Steps   []policy.NATStep     `json:"steps"`
	Window  *fm.TimeWindow       `json:"window,omitempty"`
}

type reconstructionPolicy struct {
	Traffic         []flow.TrafficRegion `json:"traffic,omitempty"`
	Scope           string               `json:"scope,omitempty"`
	RuleSet         string               `json:"ruleset,omitempty"`
	FromZone        fm.ID                `json:"from_zone"`
	ToZone          fm.ID                `json:"to_zone"`
	EgressInterface fm.ID                `json:"egress_interface,omitempty"`
	At              time.Time            `json:"at,omitempty"`
}

func reconstructionPolicyOf(q policy.Request) reconstructionPolicy {
	return reconstructionPolicy{Traffic: q.Traffic.Regions(), Scope: q.Scope, RuleSet: q.RuleSet, FromZone: q.FromZone, ToZone: q.ToZone, EgressInterface: q.EgressInterface, At: q.At}
}
func reconstructionPolicies(requests []policy.Request) []reconstructionPolicy {
	out := make([]reconstructionPolicy, 0, len(requests))
	for _, q := range requests {
		out = append(out, reconstructionPolicyOf(q))
	}
	return out
}

type reconstructionNative struct {
	Policy  reconstructionPolicy  `json:"policy"`
	Packet  *reconstructionPolicy `json:"packet,omitempty"`
	VRF     string                `json:"vrf,omitempty"`
	Effects reconstructionEffects `json:"effects"`
	Sources []string              `json:"sources,omitempty"`
}

func reconstructionNatives(inputs []NativeRequest) []reconstructionNative {
	out := make([]reconstructionNative, len(inputs))
	for i, r := range inputs {
		out[i] = reconstructionNative{Policy: reconstructionPolicyOf(r.Request), Effects: reconstructionEffects{Additions: r.Additions, Lifetime: r.Lifetime}, Sources: r.Sources}
		if r.Packet != nil {
			p := reconstructionPolicyOf(r.Packet.Request)
			out[i].Packet = &p
			out[i].VRF = r.Packet.VRF
		}
		for _, n := range r.NAT {
			out[i].Effects.NAT = append(out[i].Effects.NAT, reconstructionNAT{Request: reconstructionPolicyOf(n.Request), Steps: n.Steps, Window: n.Window})
		}
	}
	return out
}

func (p reconstructionPolicy) request() policy.Request {
	return policy.Request{Scope: p.Scope, RuleSet: p.RuleSet, FromZone: p.FromZone, ToZone: p.ToZone, EgressInterface: p.EgressInterface, At: p.At}
}

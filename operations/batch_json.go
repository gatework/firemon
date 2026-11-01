package operations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

const MaxRequestBytes = 4 << 20

// RequestDocument is bounded offline JSON version 1. Each traffic entry is one
// exact region, not independently cross-multiplied address/service lists.
type RequestDocument struct {
	Version  int              `json:"version"`
	Requests []AccessDocument `json:"requests"`
}
type AccessDocument struct {
	Native         *NativeDocument         `json:"native,omitempty"`
	WireCandidates []WireCandidateDocument `json:"wire_candidates,omitempty"`
	ID             string                  `json:"id,omitempty"`
	Traffic        []flow.TrafficRegion    `json:"traffic"`
	View           inventory.View          `json:"view,omitempty"`
	Scope          *string                 `json:"scope,omitempty"`
	VRF            *string                 `json:"vrf,omitempty"`
	At             time.Time               `json:"at,omitempty"`
	Targets        []TargetDocument        `json:"targets,omitempty"`
	Sources        []string                `json:"sources,omitempty"`
}
type NativeDocument struct {
	Lifetime      *plan.ScheduleIntent `json:"lifetime,omitempty"`
	PolicyTraffic []flow.TrafficRegion `json:"policy_traffic,omitempty"`
	Additions     plan.NativeAdditions `json:"additions"`
	NAT           []NATIntentDocument  `json:"nat"`
}
type NATIntentDocument struct {
	Request PolicyDocument   `json:"request"`
	Steps   []policy.NATStep `json:"steps"`
	Window  *fm.TimeWindow   `json:"window,omitempty"`
}

type WireCandidateDocument struct {
	Traffic []flow.TrafficRegion `json:"traffic"`
	Target  TargetDocument       `json:"target"`
}

type TargetDocument struct {
	Device   string         `json:"device"`
	Revision string         `json:"revision,omitempty"`
	Policy   PolicyDocument `json:"policy"`
	VRF      string         `json:"vrf,omitempty"`
	Packet   bool           `json:"packet,omitempty"`
}
type PolicyDocument struct {
	Traffic         []flow.TrafficRegion `json:"traffic,omitempty"`
	Scope           string               `json:"scope,omitempty"`
	RuleSet         string               `json:"ruleset,omitempty"`
	FromZone        fm.ID                `json:"from_zone"`
	ToZone          fm.ID                `json:"to_zone"`
	EgressInterface fm.ID                `json:"egress_interface,omitempty"`
	At              time.Time            `json:"at,omitempty"`
}

func decodeBounded(reader io.Reader, value any) error {
	if dependency.Nil(reader) {
		return ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(reader, MaxRequestBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > MaxRequestBytes {
		return fmt.Errorf("%w: request exceeds byte limit", ErrInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("%w: trailing JSON", ErrInvalid)
	}
	return nil
}
func DecodeBatchRequest(reader io.Reader) (BatchRequest, error) {
	var document RequestDocument
	if err := decodeBounded(reader, &document); err != nil {
		return BatchRequest{}, err
	}
	if document.Version != 1 || len(document.Requests) == 0 || len(document.Requests) > 100 {
		return BatchRequest{}, ErrInvalid
	}
	out := BatchRequest{Version: 1}
	regions := 0
	for _, a := range document.Requests {
		regions += len(a.Traffic)
		if regions > 4096 || len(a.Targets) > 100 {
			return BatchRequest{}, ErrInvalid
		}
		traffic, err := flow.NewTraffic(4096, a.Traffic...)
		if err != nil {
			return BatchRequest{}, err
		}
		if a.View != "" && a.View != inventory.Original && a.View != inventory.Real && a.View != inventory.Translated {
			return BatchRequest{}, ErrInvalid
		}
		req := AccessRequest{ID: a.ID, Traffic: traffic, View: a.View, Scope: a.Scope, VRF: a.VRF, At: a.At, Sources: a.Sources}
		if a.Native != nil {
			if len(a.Native.NAT) == 0 && a.Native.Lifetime == nil || len(a.Native.NAT) > 100 || len(a.Targets) != 1 || len(a.WireCandidates) != 0 {
				return BatchRequest{}, ErrInvalid
			}
			n := &NativeEffects{Additions: a.Native.Additions, Lifetime: a.Native.Lifetime}
			regions += len(a.Native.PolicyTraffic)
			if regions > 4096 {
				return BatchRequest{}, ErrInvalid
			}
			n.PolicyTraffic, err = flow.NewTraffic(4096, a.Native.PolicyTraffic...)
			if err != nil {
				return BatchRequest{}, err
			}
			for _, i := range a.Native.NAT {
				regions += len(i.Request.Traffic)
				if regions > 4096 || len(i.Steps) > 100 {
					return BatchRequest{}, ErrInvalid
				}
				q := i.Request.request()
				q.Traffic, err = flow.NewTraffic(4096, i.Request.Traffic...)
				if err != nil {
					return BatchRequest{}, err
				}
				n.NAT = append(n.NAT, policy.NATIntent{Request: q, Steps: i.Steps, Window: i.Window})
			}
			req.Native = n
		}
		for _, target := range a.Targets {
			if len(target.Policy.Traffic) > 0 || target.Device == "" {
				return BatchRequest{}, ErrInvalid
			}
			req.Targets = append(req.Targets, AccessTarget{Device: target.Device, Revision: target.Revision, Request: target.Policy.request(), VRF: target.VRF, Packet: target.Packet})
		}
		if len(a.WireCandidates) > 100 || len(a.WireCandidates) > 0 && (len(a.Targets) > 0 || (a.View != inventory.Translated && a.View != inventory.Real)) {
			return BatchRequest{}, ErrInvalid
		}
		for _, candidate := range a.WireCandidates {
			regions += len(candidate.Traffic)
			if regions > 4096 || candidate.Target.Device == "" || len(candidate.Target.Policy.Traffic) > 0 {
				return BatchRequest{}, ErrInvalid
			}
			traffic, err := flow.NewTraffic(4096, candidate.Traffic...)
			if err != nil {
				return BatchRequest{}, err
			}
			req.WireCandidates = append(req.WireCandidates, WireCandidate{Traffic: traffic, Target: AccessTarget{Device: candidate.Target.Device, Revision: candidate.Target.Revision, Request: candidate.Target.Policy.request(), VRF: candidate.Target.VRF, Packet: true}})
		}
		out.Requests = append(out.Requests, req)
	}
	return out, nil
}
func DecodeTopology(reader io.Reader) (inventory.Topology, error) {
	var top inventory.Topology
	if err := decodeBounded(reader, &top); err != nil {
		return top, err
	}
	return top, top.Validate()
}
func (p PolicyDocument) request() policy.Request {
	return policy.Request{Scope: p.Scope, RuleSet: p.RuleSet, FromZone: p.FromZone, ToZone: p.ToZone, EgressInterface: p.EgressInterface, At: p.At}
}
func policyDocument(q policy.Request) PolicyDocument {
	return PolicyDocument{Traffic: q.Traffic.Regions(), Scope: q.Scope, RuleSet: q.RuleSet, FromZone: q.FromZone, ToZone: q.ToZone, EgressInterface: q.EgressInterface, At: q.At}
}
func policyDocuments(requests []policy.Request) []PolicyDocument {
	out := make([]PolicyDocument, 0, len(requests))
	for _, q := range requests {
		out = append(out, policyDocument(q))
	}
	return out
}
func accessDocument(a AccessRequest) AccessDocument {
	out := AccessDocument{ID: a.ID, Traffic: a.Traffic.Regions(), View: a.View, Scope: cloneString(a.Scope), VRF: cloneString(a.VRF), At: a.At, Sources: slices.Clone(a.Sources)}
	a.Native = cloneNativeEffects(a.Native)
	if a.Native != nil {
		n := &NativeDocument{PolicyTraffic: a.Native.PolicyTraffic.Regions(), Additions: a.Native.Additions, Lifetime: a.Native.Lifetime}
		for _, i := range a.Native.NAT {
			n.NAT = append(n.NAT, NATIntentDocument{Request: policyDocument(i.Request), Steps: i.Steps, Window: i.Window})
		}
		out.Native = n
	}
	for _, target := range a.Targets {
		out.Targets = append(out.Targets, TargetDocument{Device: target.Device, Revision: target.Revision, Policy: policyDocument(target.Request), VRF: target.VRF, Packet: target.Packet})
	}
	for _, c := range a.WireCandidates {
		out.WireCandidates = append(out.WireCandidates, WireCandidateDocument{Traffic: c.Traffic.Regions(), Target: TargetDocument{Device: c.Target.Device, Revision: c.Target.Revision, Policy: policyDocument(c.Target.Request), VRF: c.Target.VRF, Packet: c.Target.Packet}})
	}

	return out
}

type ReportDocument struct {
	Topology   *inventory.Topology `json:"topology,omitempty"`
	Version    int                 `json:"version"`
	Generation uint64              `json:"generation"`
	Inputs     []InputDocument     `json:"inputs"`
	Devices    []DeviceDocument    `json:"devices"`
	Issues     []IssueDocument     `json:"issues"`
}
type InputDocument struct {
	Index    int               `json:"index"`
	Request  AccessDocument    `json:"request"`
	Outcomes []OutcomeDocument `json:"outcomes"`
}
type OutcomeDocument struct {
	Real           []flow.TrafficRegion  `json:"real"`
	Sources        []string              `json:"sources,omitempty"`
	Device         string                `json:"device"`
	Revision       string                `json:"revision"`
	Wire           []flow.TrafficRegion  `json:"wire"`
	NativeRequests []PolicyDocument      `json:"native_requests"`
	Policy         CoverageDocument      `json:"policy"`
	NAT            NATDocument           `json:"nat"`
	Disposition    plan.BatchDisposition `json:"disposition"`
}
type CoverageDocument struct {
	Complete  bool                 `json:"complete"`
	Allowed   []flow.TrafficRegion `json:"allowed"`
	Denied    []flow.TrafficRegion `json:"denied"`
	Unknown   []flow.TrafficRegion `json:"unknown"`
	Unmatched []flow.TrafficRegion `json:"unmatched"`
	Decisions []DecisionDocument   `json:"decisions"`
}
type DecisionDocument struct {
	Rule    fm.ID                `json:"rule"`
	Action  fm.Action            `json:"action"`
	Traffic []flow.TrafficRegion `json:"traffic"`
	Known   bool                 `json:"known"`
}
type NATDocument struct {
	Original           []flow.TrafficRegion `json:"original"`
	Translated         []flow.TrafficRegion `json:"translated"`
	Steps              []policy.NATStep     `json:"steps"`
	Exact              bool                 `json:"exact"`
	PossibleAllocation bool                 `json:"possible_allocation"`
}
type IssueDocument struct {
	TrafficView string               `json:"traffic_view"`
	Input       int                  `json:"input"`
	Device      string               `json:"device,omitempty"`
	Stage       string               `json:"stage"`
	Code        string               `json:"code"`
	Message     string               `json:"message,omitempty"`
	Traffic     []flow.TrafficRegion `json:"traffic"`
	Sources     []string             `json:"sources,omitempty"`
}
type BatchSourceDocument struct {
	Index   int `json:"index"`
	Input   int `json:"input"`
	Outcome int `json:"outcome"`
}
type DeviceDocument struct {
	Sources        []BatchSourceDocument `json:"sources"`
	Device         string                `json:"device"`
	Revision       string                `json:"revision"`
	SemanticDigest string                `json:"semantic_digest"`
	Inputs         []BatchInputDocument  `json:"inputs"`
	Plan           *PlanDocument         `json:"plan,omitempty"`
}
type BatchInputDocument struct {
	Index       int                   `json:"index"`
	Request     PolicyDocument        `json:"request"`
	Disposition plan.BatchDisposition `json:"disposition"`
	Attempts    []plan.BatchAttempt   `json:"attempts,omitempty"`
}

// PlanDocument is a review artifact, not an executable reconstruction token.
// Durable reconstruction and approval are separate operations.
type PlanDocument struct {
	NativeOptions *plan.NativeOptions    `json:"native_options,omitempty"`
	NativeChanges *plan.NativeChanges    `json:"native_changes,omitempty"`
	NATProof      *policy.NATProof       `json:"nat_proof,omitempty"`
	NativeInputs  []NativeInputDocument  `json:"native_inputs,omitempty"`
	PacketProofs  []NativePacketDocument `json:"packet_proofs,omitempty"`
	Digest        string                 `json:"digest"`
	Targets       []PolicyDocument       `json:"targets"`
	InputRequests []PolicyDocument       `json:"input_requests"`
	Proof         plan.Proof             `json:"proof"`
	Cost          plan.Cost              `json:"cost"`
	Changes       []plan.Change          `json:"changes"`
	Commands      []string               `json:"commands"`
}

func coverageDocument(r policy.Result) CoverageDocument {
	out := CoverageDocument{Complete: r.Complete, Allowed: r.Allowed.Regions(), Denied: r.Denied.Regions(), Unknown: r.Unknown.Regions(), Unmatched: r.Unmatched.Regions()}
	for _, d := range r.Decisions {
		out.Decisions = append(out.Decisions, DecisionDocument{Rule: d.Rule, Action: d.Action, Traffic: d.Traffic.Regions(), Known: d.Known})
	}
	return out
}
func (r BatchReport) Document() ReportDocument {
	out := ReportDocument{Version: r.Version, Generation: r.Generation}
	if r.Topology != nil {
		t := *r.Topology
		t.Bindings = slices.Clone(t.Bindings)
		for i := range t.Bindings {
			t.Bindings[i].Networks = slices.Clone(t.Bindings[i].Networks)
			t.Bindings[i].Sources = slices.Clone(t.Bindings[i].Sources)
		}
		out.Topology = &t
	}
	for _, input := range r.Inputs {
		row := InputDocument{Index: input.Index, Request: accessDocument(input.Request)}
		for _, o := range input.Outcomes {
			row.Outcomes = append(row.Outcomes, OutcomeDocument{Device: o.Device, Revision: o.Revision, Wire: o.Wire.Regions(), Real: o.Real.Regions(), NativeRequests: policyDocuments(o.NativeRequests), Sources: slices.Clone(o.Sources), Policy: coverageDocument(o.Policy), NAT: NATDocument{Original: o.NAT.Original.Regions(), Translated: o.NAT.Translated.Regions(), Steps: slices.Clone(o.NAT.Steps), Exact: o.NAT.Exact, PossibleAllocation: o.NAT.PossibleAllocation}, Disposition: o.Disposition})
		}
		out.Inputs = append(out.Inputs, row)
	}
	for _, issue := range r.Issues {
		out.Issues = append(out.Issues, IssueDocument{Input: issue.Input, TrafficView: issue.TrafficView, Device: issue.Device, Stage: issue.Stage, Code: issue.Code, Message: issue.Message, Traffic: issue.Traffic.Regions(), Sources: slices.Clone(issue.Sources)})
	}
	for _, device := range r.Devices {
		row := DeviceDocument{Device: device.Device, Revision: device.Revision, SemanticDigest: device.SemanticDigest}
		for _, source := range device.Sources {
			row.Sources = append(row.Sources, BatchSourceDocument{Index: source.Index, Input: source.Input, Outcome: source.Outcome})
		}
		for _, input := range device.Batch.Inputs {
			row.Inputs = append(row.Inputs, BatchInputDocument{Index: input.Index, Request: policyDocument(input.Request), Disposition: input.Disposition, Attempts: slices.Clone(input.Attempts)})
		}
		if p := device.Batch.Plan; p != nil {
			row.Plan = &PlanDocument{Digest: p.Digest(), Targets: policyDocuments(p.Targets()), InputRequests: policyDocuments(p.InputRequests()), Proof: p.Proof(), Cost: p.Cost(), Changes: p.Changes(), Commands: p.Commands()}
			if p.NativeInputs() != nil {
				options := p.NativeOptions()
				row.Plan.NativeOptions = &options
				c := p.NativeChanges()
				row.Plan.NativeChanges = &c
				row.Plan.NATProof = p.NATProof()
				row.Plan.NativeInputs = nativeInputDocuments(p.NativeInputs())
				for _, packet := range p.PacketProofs() {
					row.Plan.PacketProofs = append(row.Plan.PacketProofs, NativePacketDocument{Request: policyDocument(packet.Request), VRF: packet.VRF})
				}
			}
		}
		out.Devices = append(out.Devices, row)
	}
	return out
}

func cloneString(p *string) *string {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

type NativeInputDocument struct {
	Policy  PolicyDocument  `json:"policy"`
	Packet  *PolicyDocument `json:"packet,omitempty"`
	VRF     string          `json:"vrf,omitempty"`
	Effects NativeDocument  `json:"effects"`
	Sources []string        `json:"sources,omitempty"`
}

func nativeInputDocuments(inputs []plan.NativeRequest) []NativeInputDocument {
	out := make([]NativeInputDocument, len(inputs))
	for i, r := range inputs {
		out[i] = NativeInputDocument{Policy: policyDocument(r.Request), Effects: NativeDocument{Additions: r.Additions, Lifetime: r.Lifetime}, Sources: r.Sources}
		if r.Packet != nil {
			p := policyDocument(r.Packet.Request)
			out[i].Packet = &p
			out[i].VRF = r.Packet.VRF
		}
		for _, n := range r.NAT {
			out[i].Effects.NAT = append(out[i].Effects.NAT, NATIntentDocument{Request: policyDocument(n.Request), Steps: n.Steps, Window: n.Window})
		}
	}
	return out
}

type NativePacketDocument struct {
	Request PolicyDocument `json:"request"`
	VRF     string         `json:"vrf,omitempty"`
}

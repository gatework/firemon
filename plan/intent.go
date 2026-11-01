package plan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

// planIntent is closed to this package. Each successful construction transfers
// one owned intent into Plan; optional result fields never select proof meaning.
// Approval encodings intentionally differ from reconstruction encodings.
type planIntent interface {
	approval(*Plan) ([]byte, error)
	verify(context.Context, *Plan, *fm.Firewall, *fm.Firewall, *visitBudget) error
}

type accessIntent struct{ target policy.Request }
type batchIntent struct {
	inputs, targets []policy.Request
	options         BatchOptions
}
type nativeIntent struct {
	inputs, accepted []NativeRequest
	options          NativeOptions
}
type preservationIntent struct{ proof policy.Equivalence }
type transferIntent struct {
	inputs []RuleIntent
	from   time.Time
}

func (i accessIntent) verify(ctx context.Context, p *Plan, before, after *fm.Firewall, visits *visitBudget) error {
	_, err := (Planner{Engine: p.engine}).proveWithBaseline(ctx, before, after, i.target, nil, visits)
	return err
}
func (i batchIntent) verify(ctx context.Context, p *Plan, before, after *fm.Firewall, visits *visitBudget) error {
	_, err := (Planner{Engine: p.engine}).proveBatch(ctx, before, after, i.targets, nil, visits)
	return err
}
func (i nativeIntent) verify(ctx context.Context, p *Plan, before, after *fm.Firewall, visits *visitBudget) error {
	_, _, err := (Planner{Engine: p.engine}).proveNative(ctx, before, after, i.accepted, visits)
	return err
}
func (i preservationIntent) verify(ctx context.Context, p *Plan, before, after *fm.Firewall, _ *visitBudget) error {
	_, err := p.engine.Equivalent(ctx, before, after, i.proof.From)
	return err
}
func (i transferIntent) verify(ctx context.Context, p *Plan, before, after *fm.Firewall, visits *visitBudget) error {
	_, err := (Planner{Engine: p.engine}).proveTransfers(ctx, before, after, p.changes, i.from, visits)
	return err
}

func (p *Plan) seal() error {
	if p.intent == nil {
		return ErrInvalid
	}
	b, err := p.intent.approval(p)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	p.digest = hex.EncodeToString(sum[:])
	return nil
}

func (i accessIntent) approval(p *Plan) ([]byte, error) {
	return legacyApproval(p, i.target, nil, nil, time.Time{})
}
func (i preservationIntent) approval(p *Plan) ([]byte, error) {
	return legacyApproval(p, policy.Request{}, &i.proof, nil, time.Time{})
}
func (i transferIntent) approval(p *Plan) ([]byte, error) {
	return legacyApproval(p, policy.Request{}, nil, i.inputs, i.from)
}

// Preserve the historical field order, empty transfer array and zero target for
// lifecycle plans. This representation is approval material, not a replay input.
func legacyApproval(p *Plan, target policy.Request, preservation *policy.Equivalence, inputs []RuleIntent, from time.Time) ([]byte, error) {
	type transfer struct {
		Intent  RuleIntent
		Traffic []flow.TrafficRegion
	}
	targets := make([]transfer, 0, len(inputs))
	for _, intent := range inputs {
		targets = append(targets, transfer{intent, intent.Request.Traffic.Regions()})
	}
	return json.Marshal(struct {
		Proof        Proof
		Changes      []Change
		Commands     []string
		Target       policy.Request
		Traffic      []flow.TrafficRegion
		Preservation *policy.Equivalence
		Transfers    []transfer
		TransferFrom time.Time
	}{p.proof, p.changes, p.commands, target, target.Traffic.Regions(), preservation, targets, from})
}

func (i batchIntent) approval(p *Plan) ([]byte, error) {
	type target struct {
		Request policy.Request
		Traffic []flow.TrafficRegion
	}
	targets := make([]target, len(i.targets))
	for n, q := range i.targets {
		targets[n] = target{q, q.Traffic.Regions()}
	}
	// Effective options and original rejected inputs remain replay-only metadata.
	return json.Marshal(struct {
		Version  int
		Proof    Proof
		Changes  []Change
		Commands []string
		Targets  []target
	}{1, p.proof, p.changes, p.commands, targets})
}

func (i nativeIntent) approval(p *Plan) ([]byte, error) {
	type intent struct {
		Request policy.Request
		Traffic []flow.TrafficRegion
		Steps   []policy.NATStep
		Window  *fm.TimeWindow `json:",omitempty"`
	}
	type input struct {
		Packet        *policy.PacketRequest
		PacketTraffic []flow.TrafficRegion
		Request       policy.Request
		Traffic       []flow.TrafficRegion
		Additions     NativeAdditions
		NAT           []intent
		Sources       []string
		Lifetime      *ScheduleIntent `json:",omitempty"`
	}
	encode := func(in []NativeRequest) []input {
		out := make([]input, len(in))
		for n, r := range in {
			out[n] = input{Packet: r.Packet, Request: normalizedRequest(r.Request), Traffic: nativeTrafficRegions(r.Request.Traffic), Additions: r.Additions, Sources: r.Sources, Lifetime: r.Lifetime}
			if r.Packet != nil {
				out[n].PacketTraffic = r.Packet.Traffic.Regions()
			}
			for _, nat := range r.NAT {
				out[n].NAT = append(out[n].NAT, intent{normalizedRequest(nat.Request), nativeTrafficRegions(nat.Request.Traffic), nat.Steps, nat.Window})
			}
		}
		return out
	}
	version := 2
	for _, r := range i.inputs {
		if r.Lifetime != nil {
			version = 3
			break
		}
	}
	return json.Marshal(struct {
		Version          int
		Options          NativeOptions
		Proof            Proof
		NATProof         *policy.NATProof
		Changes          NativeChanges
		Inputs, Accepted []input
		Commands         []string
	}{version, i.options, p.proof, p.natProof, p.nativeChanges, encode(i.inputs), encode(i.accepted), p.commands})
}

// Targets returns the normalized jointly proven batch targets. Single-context
// legacy plans return their one target; lifecycle plans may have no targets.
func (p *Plan) Targets() []policy.Request {
	if p == nil {
		return nil
	}
	switch i := p.intent.(type) {
	case accessIntent:
		if !i.target.Traffic.Empty() {
			return []policy.Request{i.target}
		}
	case batchIntent:
		return slices.Clone(i.targets)
	case nativeIntent:
		out := make([]policy.Request, len(i.accepted))
		for n, r := range i.accepted {
			out[n] = normalizedRequest(r.Request)
		}
		return out
	}
	return nil
}

// InputRequests retains original batch inputs. Traffic values are immutable;
// the returned container is detached from the plan.
func (p *Plan) InputRequests() []policy.Request {
	if p == nil {
		return nil
	}
	switch i := p.intent.(type) {
	case batchIntent:
		return slices.Clone(i.inputs)
	case nativeIntent:
		out := make([]policy.Request, len(i.inputs))
		for n, r := range i.inputs {
			out[n] = r.Request
		}
		return out
	}
	return nil
}
func (p *Plan) BatchOptions() BatchOptions {
	if i, ok := p.intent.(batchIntent); ok {
		return i.options
	}
	return BatchOptions{}
}
func (p *Plan) NativeOptions() NativeOptions {
	if i, ok := p.intent.(nativeIntent); ok {
		return i.options
	}
	return NativeOptions{}
}
func (p *Plan) NativeInputs() []NativeRequest {
	if i, ok := p.intent.(nativeIntent); ok {
		return cloneNativeInputs(i.inputs)
	}
	return nil
}
func (p *Plan) Preservation() (policy.Equivalence, bool) {
	if p != nil {
		if i, ok := p.intent.(preservationIntent); ok {
			return i.proof, true
		}
	}
	return policy.Equivalence{}, false
}

// PacketProofs lists only independently proven native packet requests. Empty
// means policy-view plus NAT proof, not a proven packet pipeline.
func (p *Plan) PacketProofs() []policy.PacketRequest {
	var out []policy.PacketRequest
	if i, ok := p.intent.(nativeIntent); ok {
		for _, r := range i.accepted {
			if r.Packet != nil {
				out = append(out, *r.Packet)
			}
		}
	}
	return out
}

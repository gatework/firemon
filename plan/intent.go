package plan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/policy"
)

// planIntent is closed to this package. Each successful construction transfers
// one owned intent into Plan; optional result fields never select proof meaning.
// Approval encodings intentionally differ from reconstruction encodings.
type planIntent interface {
	approval(*Plan) ([]byte, error)
	verify(context.Context, *Plan, *fm.Firewall, *fm.Firewall, *visitBudget) error
}

type accessIntent struct {
	target  policy.Request
	options BatchOptions
}
type batchIntent struct {
	inputs, targets []policy.Request
	options         BatchOptions
}
type nativeIntent struct {
	inputs, accepted []NativeRequest
	options          NativeOptions
}
type preservationIntent struct {
	proof   policy.Equivalence
	options BatchOptions
}
type transferIntent struct {
	inputs  []RuleIntent
	from    time.Time
	options BatchOptions
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

// encodeApproval gives every business intent the same explicit approval boundary.
// The payload describes that intent; replay material is validated separately and
// always re-runs its proof before it can produce the same approval digest.
func encodeApproval[T any](p *Plan, kind string, payload T) ([]byte, error) {
	return json.Marshal(struct {
		Version       int
		Kind          string
		Before, After string
		Proof         Proof
		NATProof      *policy.NATProof
		Changes       []Change
		NativeChanges NativeChanges
		Commands      []string
		Payload       T
	}{4, kind, p.before.SemanticDigest(), p.after.SemanticDigest(), p.proof,
		p.natProof, p.changes, p.nativeChanges, p.commands, payload})
}

func (p Planner) effectiveOptions() BatchOptions {
	return BatchOptions{MaxCandidates: newCandidateAttempts(p.MaxCandidates).limit, Limits: p.Engine.Limits.WithDefaults()}
}

func (i accessIntent) approval(p *Plan) ([]byte, error) {
	return encodeApproval(p, "access", struct {
		Target  reconstructionPolicy
		Options BatchOptions
	}{reconstructionPolicyOf(i.target), i.options})
}
func (i preservationIntent) approval(p *Plan) ([]byte, error) {
	return encodeApproval(p, "preserve", struct {
		Equivalence policy.Equivalence
		Options     BatchOptions
	}{i.proof, i.options})
}
func (i transferIntent) approval(p *Plan) ([]byte, error) {
	return encodeApproval(p, "transfer", struct {
		Inputs  []reconstructionTransfer
		From    time.Time
		Options BatchOptions
	}{reconstructionTransfers(i.inputs), i.from, i.options})
}
func (i batchIntent) approval(p *Plan) ([]byte, error) {
	return encodeApproval(p, "policy", struct {
		Targets []reconstructionPolicy
		Options BatchOptions
	}{reconstructionPolicies(i.targets), i.options})
}
func (i nativeIntent) approval(p *Plan) ([]byte, error) {
	return encodeApproval(p, "native", struct {
		Inputs, Accepted []reconstructionNative
		Options          NativeOptions
	}{reconstructionNatives(i.inputs), reconstructionNatives(i.accepted), i.options})
}

// Targets returns the normalized jointly proven batch targets. Single-context
// access plans return their one target; lifecycle plans may have no targets.
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

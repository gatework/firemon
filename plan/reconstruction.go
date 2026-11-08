package plan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/internal/jsonio"
	"github.com/gatework/firemon/policy"
)

// MaxReconstructionBytes bounds the current reconstruction envelope.
const MaxReconstructionBytes = 4 << 20
const reconstructionAlgorithm = "firemon-business-v2"

// ErrReconstruction identifies unsupported, corrupt or nonmatching replay material.
var ErrReconstruction = errors.New("unsupported, corrupt or nonmatching plan reconstruction")

// SnapshotRevisions identifies the immutable snapshots retained with a plan.
// Source is required only for migration; Baseline is always the target snapshot.
type SnapshotRevisions struct{ Baseline, Source string }

// ReconstructionSnapshots supplies independently validated immutable captures.
// Migration requires both snapshots; other intents reject an extraneous source.
type ReconstructionSnapshots struct{ Baseline, Source *fm.Firewall }

// Reconstruction is owned, validated input for re-running the original planner.
// It is not an approved Plan. Its zero value cannot be rebuilt. Decoded values
// are immutable and may be used by independent concurrent rebuilds.
type Reconstruction struct {
	revision                   string
	baseline                   fm.Metadata
	semanticDigest, planDigest string
	intent                     planIntent
	preservation               *reconstructionPreservation
	source                     *reconstructionSnapshot
}

// Revision identifies the immutable snapshot to load, never a current head.
func (r *Reconstruction) Revision() string {
	if r == nil {
		return ""
	}
	return r.revision
}

// SourceRevision identifies the immutable migration source, or is empty.
func (r *Reconstruction) SourceRevision() string {
	if r == nil || r.source == nil {
		return ""
	}
	return r.source.Revision
}

type reconstructionSnapshot struct {
	Revision       string      `json:"revision"`
	Metadata       fm.Metadata `json:"metadata"`
	SemanticDigest string      `json:"semantic_digest"`
}

type reconstructionDocument struct {
	Version          int                         `json:"version"`
	Algorithm        string                      `json:"algorithm"`
	Mode             string                      `json:"mode"`
	BaselineRevision string                      `json:"baseline_revision"`
	Baseline         fm.Metadata                 `json:"baseline"`
	SemanticDigest   string                      `json:"semantic_digest"`
	PlanDigest       string                      `json:"plan_digest"`
	Options          BatchOptions                `json:"options"`
	Policy           []reconstructionPolicy      `json:"policy,omitempty"`
	Native           []reconstructionNative      `json:"native,omitempty"`
	Preservation     *reconstructionPreservation `json:"preservation,omitempty"`
	Transfers        []reconstructionTransfer    `json:"transfers,omitempty"`
	From             *time.Time                  `json:"from,omitempty"`
	Source           *reconstructionSnapshot     `json:"source,omitempty"`
	Migration        *MigrationInput             `json:"migration,omitempty"`
}

// EncodeReconstruction writes bounded, versioned business inputs. Retain its
// checksum independently and retain the referenced immutable snapshot. Commands
// and proof flags are never imported as authority during reconstruction.
func EncodeReconstruction(ctx context.Context, writer io.Writer, revisions SnapshotRevisions, p *Plan) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if dependency.Nil(writer) || !validReconstructionChecksum(revisions.Baseline) || p == nil || p.before == nil || !validReconstructionChecksum(p.digest) {
		return "", ErrReconstruction
	}
	d := reconstructionDocument{Version: 2, Algorithm: reconstructionAlgorithm, BaselineRevision: revisions.Baseline, Baseline: p.before.Metadata(), SemanticDigest: p.before.SemanticDigest(), PlanDigest: p.digest}
	if _, migration := p.intent.(migrationIntent); !migration && revisions.Source != "" {
		return "", ErrReconstruction
	}
	switch i := p.intent.(type) {
	case migrationIntent:
		if i.source == nil || !validReconstructionChecksum(revisions.Source) {
			return "", ErrReconstruction
		}
		d.Mode, d.Options = "migration", BatchOptions{MaxCandidates: i.options.MaxCandidates, Limits: i.options.Limits}
		d.Source = &reconstructionSnapshot{Revision: revisions.Source, Metadata: i.source.Metadata(), SemanticDigest: i.source.SemanticDigest()}
		input := cloneMigrationInput(i.input)
		d.Migration = &input
	case accessIntent:
		d.Mode, d.Options, d.Policy = "access", i.options, reconstructionPolicies([]policy.Request{i.target})
	case preservationIntent:
		d.Mode, d.Options = "preserve", i.options
		d.Preservation = &reconstructionPreservation{Candidate: p.after.Export(), Changes: p.Changes(), From: i.proof.From}
	case transferIntent:
		d.Mode, d.Options, d.Transfers, d.From = "transfer", i.options, reconstructionTransfers(i.inputs), &i.from
	case batchIntent:
		d.Mode, d.Options, d.Policy = "policy", i.options, reconstructionPolicies(i.inputs)
	case nativeIntent:
		d.Mode, d.Options, d.Native = "native", BatchOptions{MaxCandidates: i.options.MaxCandidates, Limits: i.options.Limits}, reconstructionNatives(i.inputs)
	default:
		return "", ErrReconstruction
	}
	if err := d.validate(); err != nil {
		return "", err
	}
	raw, err := jsonio.Encode(ctx, d, MaxReconstructionBytes)
	if err == jsonio.ErrLimit {
		return "", ErrReconstruction
	}
	if err != nil {
		return "", err
	}
	n, err := writer.Write(raw)
	if err != nil {
		return "", err
	}
	if n != len(raw) {
		return "", io.ErrShortWrite
	}
	return reconstructionChecksum(raw), ctx.Err()
}

// DecodeReconstruction validates checksum, format and bounded input containers
// before materializing owned inputs. It performs no snapshot reads or rendering.
func DecodeReconstruction(ctx context.Context, reader io.Reader, expected string) (*Reconstruction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validReconstructionChecksum(expected) {
		return nil, ErrReconstruction
	}
	if dependency.Nil(reader) {
		return nil, ErrInvalid
	}
	raw, err := jsonio.Read(ctx, reader, MaxReconstructionBytes)
	if err == jsonio.ErrLimit {
		return nil, ErrReconstruction
	}
	if err != nil {
		return nil, err
	}
	if reconstructionChecksum(raw) != expected {
		return nil, ErrReconstruction
	}
	var d reconstructionDocument
	if err := jsonio.Decode(raw, &d); err != nil {
		if err == jsonio.ErrTrailing {
			return nil, ErrReconstruction
		}
		return nil, errors.Join(ErrReconstruction, err)
	}
	if err := d.validate(); err != nil {
		return nil, err
	}
	// Charge JSON region containers before NewTraffic can normalize/materialize.
	remaining := d.Options.Limits.MaxVisits
	charge := func(q reconstructionPolicy) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(q.Traffic) > d.Options.Limits.MaxRegions || len(q.Traffic) > remaining {
			return policy.ErrBudget
		}
		remaining -= len(q.Traffic)
		return nil
	}
	for _, q := range d.Policy {
		if err := charge(q); err != nil {
			return nil, err
		}
	}
	for _, n := range d.Native {
		if n.Packet == nil && n.VRF != "" {
			return nil, ErrReconstruction
		}
		if err := charge(n.Policy); err != nil {
			return nil, err
		}
		if n.Packet != nil {
			if err := charge(*n.Packet); err != nil {
				return nil, err
			}
		}
		for _, intent := range n.Effects.NAT {
			if err := charge(intent.Request); err != nil {
				return nil, err
			}
		}
	}
	for _, intent := range d.Transfers {
		if err := charge(intent.Request); err != nil {
			return nil, err
		}
	}
	if d.Preservation != nil {
		budget := visitBudget(remaining)
		if err := preflightPreservation(ctx, d.Preservation, &budget); err != nil {
			return nil, err
		}
		remaining = int(budget)
	}
	if d.Migration != nil {
		budget := visitBudget(remaining)
		if err := budget.nativeCounts(ctx, len(d.Migration.Contexts), len(d.Migration.Rules), len(d.Migration.StaticNATs), len(d.Migration.DynamicNATs), len(d.Migration.Interfaces), len(d.Migration.VRFs)); err != nil {
			return nil, err
		}
		remaining = int(budget)
	}
	requests := make([]policy.Request, len(d.Policy))
	for i, q := range d.Policy {
		requests[i], err = restoreRequest(q, d.Options.Limits.MaxRegions)
		if err != nil {
			return nil, err
		}
	}
	native := make([]NativeRequest, len(d.Native))
	natCapacity := remaining
	for i, n := range d.Native {
		native[i] = NativeRequest{Additions: n.Effects.Additions, Lifetime: n.Effects.Lifetime, Sources: n.Sources}
		if len(n.Effects.NAT) > natCapacity {
			return nil, policy.ErrBudget
		}
		natCapacity -= len(n.Effects.NAT)
		native[i].NAT = make([]policy.NATIntent, len(n.Effects.NAT))
		for j, intent := range n.Effects.NAT {
			native[i].NAT[j] = policy.NATIntent{Steps: intent.Steps, Window: intent.Window}
		}
	}
	if len(native) > 0 {
		if remaining <= 0 {
			return nil, policy.ErrBudget
		}
		limits := d.Options.Limits
		limits.MaxVisits = remaining
		if err := PreflightNativeRequests(ctx, native, limits); err != nil {
			return nil, err
		}
		for i, n := range d.Native {
			native[i].Request, err = restoreRequest(n.Policy, limits.MaxRegions)
			if err != nil {
				return nil, err
			}
			if n.Packet != nil {
				q, err := restoreRequest(*n.Packet, limits.MaxRegions)
				if err != nil {
					return nil, err
				}
				native[i].Packet = &policy.PacketRequest{Request: q, VRF: n.VRF}
			}
			for j, intent := range n.Effects.NAT {
				native[i].NAT[j].Request, err = restoreRequest(intent.Request, limits.MaxRegions)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	var input planIntent
	switch d.Mode {
	case "migration":
		input = migrationIntent{input: cloneMigrationInput(*d.Migration), options: NativeOptions{MaxCandidates: d.Options.MaxCandidates, Limits: d.Options.Limits}}
	case "access":
		input = accessIntent{target: requests[0], options: d.Options}
	case "policy":
		input = batchIntent{inputs: requests, options: d.Options}
	case "native":
		input = nativeIntent{inputs: native, options: NativeOptions{MaxCandidates: d.Options.MaxCandidates, Limits: d.Options.Limits}}
	case "preserve":
		input = preservationIntent{proof: policy.Equivalence{From: d.Preservation.From}, options: d.Options}
	case "transfer":
		intents := make([]RuleIntent, len(d.Transfers))
		for n, i := range d.Transfers {
			q, err := restoreRequest(i.Request, d.Options.Limits.MaxRegions)
			if err != nil {
				return nil, err
			}
			intents[n] = RuleIntent{Request: q, Action: i.Action, Log: i.Log, LogStart: i.LogStart, LogEnd: i.LogEnd}
		}
		input = transferIntent{inputs: intents, from: *d.From, options: d.Options}
	}
	return &Reconstruction{revision: d.BaselineRevision, baseline: d.Baseline, semanticDigest: d.SemanticDigest, planDigest: d.PlanDigest, intent: input, preservation: d.Preservation, source: d.Source}, nil
}

// Rebuild checks an independently loaded baseline before invoking selectRenderer.
// The caller supplies its renderer adapter; saved effective options control the
// complete new planning proof. Preservation candidates are untrusted proposals;
// no saved proof flags or commands bypass validation. A changed algorithm result
// fails the approval digest check.
func (r *Reconstruction) Rebuild(ctx context.Context, snapshots ReconstructionSnapshots, selectRenderer func(string) (Renderer, error)) (*Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	baseline := snapshots.Baseline
	if r == nil || r.intent == nil || baseline == nil || !baseline.Complete() || baseline.SemanticDigest() != r.semanticDigest || !sameMetadata(baseline.Metadata(), r.baseline) {
		return nil, ErrReconstruction
	}
	if r.source == nil && snapshots.Source != nil {
		return nil, ErrReconstruction
	}
	if r.source != nil && (snapshots.Source == nil || !snapshots.Source.Complete() || snapshots.Source.SemanticDigest() != r.source.SemanticDigest || !sameMetadata(snapshots.Source.Metadata(), r.source.Metadata)) {
		return nil, ErrReconstruction
	}
	if selectRenderer == nil {
		return nil, ErrReconstruction
	}
	renderer, err := selectRenderer(baseline.Metadata().Vendor)
	if err != nil {
		return nil, err
	}
	var result BatchResult
	planner := func(options BatchOptions) Planner {
		return Planner{Renderer: renderer, Engine: policy.Engine{Limits: options.Limits}, MaxCandidates: options.MaxCandidates}
	}
	switch i := r.intent.(type) {
	case migrationIntent:
		p := planner(BatchOptions{MaxCandidates: i.options.MaxCandidates, Limits: i.options.Limits})
		p.NativeRenderer, _ = renderer.(NativeRenderer)
		result.Plan, err = p.Migrate(ctx, snapshots.Source, baseline, i.input)
	case accessIntent:
		result.Plan, err = planner(i.options).Plan(ctx, baseline, []policy.Request{i.target})
	case preservationIntent:
		if r.preservation == nil {
			return nil, ErrReconstruction
		}
		var after *fm.Firewall
		after, err = fm.Seal(r.preservation.Candidate)
		if err == nil {
			result.Plan, err = planner(i.options).Preserve(ctx, baseline, after, r.preservation.Changes, r.preservation.From)
		}
	case transferIntent:
		result.Plan, err = planner(i.options).Transfer(ctx, baseline, i.inputs, i.from)
	case batchIntent:
		p := Planner{Renderer: renderer, Engine: policy.Engine{Limits: i.options.Limits}, MaxCandidates: i.options.MaxCandidates}
		result, err = p.PlanBatch(ctx, baseline, i.inputs)
	case nativeIntent:
		nativeRenderer, _ := renderer.(NativeRenderer)
		p := Planner{Renderer: renderer, NativeRenderer: nativeRenderer, Engine: policy.Engine{Limits: i.options.Limits}, MaxCandidates: i.options.MaxCandidates}
		result, err = p.PlanNativeBatch(ctx, baseline, i.inputs)
	default:
		return nil, ErrReconstruction
	}
	if err != nil {
		return nil, err
	}
	if result.Plan == nil || result.Plan.Digest() != r.planDigest {
		return nil, ErrReconstruction
	}
	return result.Plan, ctx.Err()
}

func (d reconstructionDocument) validate() error {
	// Hard ceilings bound hostile reconstruction even when it supplies its own
	// checksum. They are format limits, not replacements for the saved budgets.
	l := d.Options.Limits
	if d.Version != 2 || d.Algorithm != reconstructionAlgorithm || !validReconstructionChecksum(d.BaselineRevision) || !validReconstructionChecksum(d.PlanDigest) || !validReconstructionChecksum(d.SemanticDigest) || d.Options.MaxCandidates < 1 || d.Options.MaxCandidates > 10000 || l.MaxVisits < 1 || l.MaxVisits > 10000000 || l.MaxRegions < 1 || l.MaxRegions > 65536 || l.MaxCombinations < 1 || l.MaxCombinations > 65536 {
		return ErrReconstruction
	}
	if d.Mode == "migration" {
		if d.Source == nil || d.Migration == nil || !validReconstructionChecksum(d.Source.Revision) || !validReconstructionChecksum(d.Source.SemanticDigest) || len(d.Migration.Contexts) == 0 || len(d.Migration.Contexts) > 100 || len(d.Policy) != 0 || len(d.Native) != 0 || len(d.Transfers) != 0 || d.Preservation != nil || d.From != nil {
			return ErrReconstruction
		}
		return nil
	}
	if d.Source != nil || d.Migration != nil {
		return ErrReconstruction
	}
	switch d.Mode {
	case "access", "policy":
		if len(d.Policy) > 0 && len(d.Policy) <= 100 && (d.Mode != "access" || len(d.Policy) == 1) && len(d.Native) == 0 && len(d.Transfers) == 0 && d.Preservation == nil && d.From == nil {
			return nil
		}
	case "native":
		if len(d.Native) > 0 && len(d.Native) <= 100 && len(d.Policy) == 0 && len(d.Transfers) == 0 && d.Preservation == nil && d.From == nil {
			return nil
		}
	case "preserve":
		if d.Preservation != nil && len(d.Policy) == 0 && len(d.Native) == 0 && len(d.Transfers) == 0 && d.From == nil {
			return nil
		}
	case "transfer":
		if len(d.Transfers) > 0 && len(d.Transfers) <= 100 && len(d.Policy) == 0 && len(d.Native) == 0 && d.Preservation == nil && d.From != nil {
			return nil
		}
	}
	return ErrReconstruction
}
func restoreRequest(d reconstructionPolicy, limit int) (policy.Request, error) {
	q := d.request()
	var err error
	q.Traffic, err = flow.NewTraffic(limit, d.Traffic...)
	return q, err
}
func sameMetadata(a, b fm.Metadata) bool {
	return a.Device == b.Device && a.Vendor == b.Vendor && a.Software == b.Software && a.Context == b.Context && a.ParserVersion == b.ParserVersion && a.SourceDigest == b.SourceDigest && a.CapturedAt.Equal(b.CapturedAt)
}
func reconstructionChecksum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func validReconstructionChecksum(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

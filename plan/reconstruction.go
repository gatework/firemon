package plan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/policy"
)

// MaxReconstructionBytes bounds the version-1 reconstruction envelope.
const MaxReconstructionBytes = 4 << 20
const reconstructionAlgorithm = "firemon-business-v1"

// ErrReconstruction identifies unsupported, corrupt or nonmatching replay material.
var ErrReconstruction = errors.New("unsupported, corrupt or nonmatching plan reconstruction")

// Reconstruction is owned, validated input for re-running the original planner.
// It is not an approved Plan. Its zero value cannot be rebuilt. Decoded values
// are immutable and may be used by independent concurrent rebuilds.
type Reconstruction struct {
	revision                   string
	baseline                   fm.Metadata
	semanticDigest, planDigest string
	intent                     planIntent
}

// Revision identifies the immutable snapshot to load, never a current head.
func (r *Reconstruction) Revision() string {
	if r == nil {
		return ""
	}
	return r.revision
}

type reconstructionDocument struct {
	Version          int                    `json:"version"`
	Algorithm        string                 `json:"algorithm"`
	Mode             string                 `json:"mode"`
	BaselineRevision string                 `json:"baseline_revision"`
	Baseline         fm.Metadata            `json:"baseline"`
	SemanticDigest   string                 `json:"semantic_digest"`
	PlanDigest       string                 `json:"plan_digest"`
	Options          BatchOptions           `json:"options"`
	Policy           []reconstructionPolicy `json:"policy,omitempty"`
	Native           []reconstructionNative `json:"native,omitempty"`
}

// EncodeReconstruction writes the existing version-1 business reconstruction
// envelope. Retain its checksum independently and retain the referenced snapshot.
// Only policy-batch and native-batch intents contain the required replay inputs.
func EncodeReconstruction(ctx context.Context, writer io.Writer, revision string, p *Plan) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if dependency.Nil(writer) || !validReconstructionChecksum(revision) || p == nil || p.before == nil || !validReconstructionChecksum(p.digest) {
		return "", ErrReconstruction
	}
	d := reconstructionDocument{Version: 1, Algorithm: reconstructionAlgorithm, BaselineRevision: revision, Baseline: p.before.Metadata(), SemanticDigest: p.before.SemanticDigest(), PlanDigest: p.digest}
	switch i := p.intent.(type) {
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
	raw, err := encodeReconstructionJSON(ctx, d, MaxReconstructionBytes)
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
	raw, err := readReconstruction(ctx, reader, MaxReconstructionBytes)
	if err != nil {
		return nil, err
	}
	if reconstructionChecksum(raw) != expected {
		return nil, ErrReconstruction
	}
	var d reconstructionDocument
	if err := decodeReconstructionJSON(raw, &d); err != nil {
		return nil, err
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
		if len(n.Effects.PolicyTraffic) != 0 || n.Packet == nil && n.VRF != "" {
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

	var input planIntent = batchIntent{inputs: requests, options: d.Options}
	if d.Mode == "native" {
		input = nativeIntent{inputs: native, options: NativeOptions{MaxCandidates: d.Options.MaxCandidates, Limits: d.Options.Limits}}
	}
	return &Reconstruction{revision: d.BaselineRevision, baseline: d.Baseline, semanticDigest: d.SemanticDigest, planDigest: d.PlanDigest, intent: input}, nil
}

// Rebuild checks an independently loaded baseline before invoking selectRenderer.
// The caller supplies its renderer adapter; saved effective options control the
// complete new planning proof. No commands, result graph or proof flags are read
// from the material. A changed algorithm result fails the approval digest check.
func (r *Reconstruction) Rebuild(ctx context.Context, baseline *fm.Firewall, selectRenderer func(string) (Renderer, error)) (*Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil || r.intent == nil || baseline == nil || !baseline.Complete() || baseline.SemanticDigest() != r.semanticDigest || !sameMetadata(baseline.Metadata(), r.baseline) {
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
	switch i := r.intent.(type) {
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
	if d.Version != 1 || d.Algorithm != reconstructionAlgorithm || !validReconstructionChecksum(d.BaselineRevision) || !validReconstructionChecksum(d.PlanDigest) || !validReconstructionChecksum(d.SemanticDigest) || d.Options.MaxCandidates < 1 || d.Options.MaxCandidates > 10000 || l.MaxVisits < 1 || l.MaxVisits > 10000000 || l.MaxRegions < 1 || l.MaxRegions > 65536 || l.MaxCombinations < 1 || l.MaxCombinations > 65536 {
		return ErrReconstruction
	}
	if d.Mode == "policy" && len(d.Policy) > 0 && len(d.Policy) <= 100 && len(d.Native) == 0 {
		return nil
	}
	if d.Mode == "native" && len(d.Native) > 0 && len(d.Native) <= 100 && len(d.Policy) == 0 {
		return nil
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
func decodeReconstructionJSON(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return errors.Join(ErrReconstruction, err)
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrReconstruction
	}
	return nil
}
func readReconstruction(ctx context.Context, reader io.Reader, limit int) ([]byte, error) {
	if dependency.Nil(reader) {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, ErrReconstruction
	}
	return raw, ctx.Err()
}

type reconstructionBuffer struct {
	bytes.Buffer
	limit int
	ctx   context.Context
}

func (b *reconstructionBuffer) Write(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > b.limit-b.Len() {
		return 0, ErrReconstruction
	}
	return b.Buffer.Write(p)
}
func encodeReconstructionJSON(ctx context.Context, value any, limit int) ([]byte, error) {
	b := reconstructionBuffer{limit: limit, ctx: ctx}
	if err := json.NewEncoder(&b).Encode(value); err != nil {
		return nil, err
	}
	return b.Bytes(), ctx.Err()
}

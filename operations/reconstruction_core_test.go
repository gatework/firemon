package operations_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors"
)

func TestCoreReconstructionOwnsConcurrentReplay(t *testing.T) {
	b := newBatchFixture(t)
	store, revision, finite := finiteReconstructionPlan(t)
	for _, tc := range []struct {
		name, revision string
		p              *plan.Plan
	}{
		{"policy", b.report.Devices[0].Revision, b.report.Devices[0].Batch.Plan},
		{"finite", revision, finite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var core bytes.Buffer
			sum, err := plan.EncodeReconstruction(t.Context(), &core, plan.SnapshotRevisions{Baseline: tc.revision}, tc.p)
			if err != nil {
				t.Fatal(err)
			}
			raw := bytes.Clone(core.Bytes())
			material, err := plan.DecodeReconstruction(t.Context(), bytes.NewReader(raw), sum)
			if err != nil || material.Revision() != tc.revision {
				t.Fatal(err)
			}
			clear(raw)
			// Decoded material is reusable, immutable input; independent rebuilds
			// cannot share mutable candidate state or skip their renderer.
			var wg sync.WaitGroup
			for range 2 {
				wg.Go(func() {
					called := 0
					p, err := material.Rebuild(t.Context(), plan.ReconstructionSnapshots{Baseline: tc.p.Before()}, func(vendor string) (plan.Renderer, error) {
						called++
						return vendors.Renderer(vendor)
					})
					if err != nil || called != 1 || p == nil || p.Digest() != tc.p.Digest() {
						t.Errorf("rebuild: called=%d err=%v", called, err)
					}
				})
			}
			wg.Wait()
			if tc.name == "finite" {
				if _, _, err := operations.RestorePlan(t.Context(), bytes.NewReader(core.Bytes()), sum, store); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestCoreReconstructionChecksBaselineBeforeRenderer(t *testing.T) {
	_, revision, p := finiteReconstructionPlan(t)
	var raw bytes.Buffer
	sum, err := plan.EncodeReconstruction(t.Context(), &raw, plan.SnapshotRevisions{Baseline: revision}, p)
	if err != nil {
		t.Fatal(err)
	}
	material, err := plan.DecodeReconstruction(t.Context(), &raw, sum)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	rendererError := errors.New("renderer unavailable")
	selectRenderer := func(string) (plan.Renderer, error) { called = true; return nil, rendererError }
	changed := p.Before().Export()
	changed.Metadata.Context = "other-context"
	wrong, err := fm.Seal(changed)
	if err != nil {
		t.Fatal(err)
	}
	for _, fw := range []*fm.Firewall{nil, wrong, p.After()} {
		if got, err := material.Rebuild(t.Context(), plan.ReconstructionSnapshots{Baseline: fw}, selectRenderer); !errors.Is(err, plan.ErrReconstruction) || got != nil || called {
			t.Fatal("renderer before baseline", err, called)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := material.Rebuild(ctx, plan.ReconstructionSnapshots{}, selectRenderer); !errors.Is(err, context.Canceled) || called {
		t.Fatal(err, called)
	}
	var zero plan.Reconstruction
	if zero.Revision() != "" {
		t.Fatal("zero material revision")
	}
	if _, err := zero.Rebuild(t.Context(), plan.ReconstructionSnapshots{Baseline: p.Before()}, selectRenderer); !errors.Is(err, plan.ErrReconstruction) || called {
		t.Fatal(err, called)
	}
	if _, err := material.Rebuild(t.Context(), plan.ReconstructionSnapshots{Baseline: p.Before()}, nil); !errors.Is(err, plan.ErrReconstruction) {
		t.Fatal(err)
	}
	if _, err := material.Rebuild(t.Context(), plan.ReconstructionSnapshots{Baseline: p.Before()}, selectRenderer); !errors.Is(err, rendererError) || !called {
		t.Fatal("renderer error lost", err)
	}
}

func TestCoreReconstructionCoversAccessPreservationAndTransfer(t *testing.T) {
	b := newBatchFixture(t)
	fw := b.report.Devices[0].Batch.Plan.Before()
	revision := b.report.Devices[0].Revision
	renderer, _ := vendors.Renderer(fw.Metadata().Vendor)
	planner := plan.Planner{Renderer: renderer}
	q := policy.Request{Traffic: requestTraffic(t, "192.0.2.10/32", "198.51.100.10/32", 443), FromZone: "inside", ToZone: "outside"}
	access, err := planner.Plan(t.Context(), fw, []policy.Request{q})
	if err != nil {
		t.Fatal(err)
	}
	preserved, err := planner.Preserve(t.Context(), fw, fw, nil, q.At)
	if err != nil {
		t.Fatal(err)
	}
	transfer, err := planner.Transfer(t.Context(), fw, []plan.RuleIntent{{Request: q, Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant}}, q.At)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*plan.Plan{access, preserved, transfer} {
		var raw bytes.Buffer
		sum, err := plan.EncodeReconstruction(t.Context(), &raw, plan.SnapshotRevisions{Baseline: revision}, p)
		if err != nil {
			t.Fatal(err)
		}
		material, err := plan.DecodeReconstruction(t.Context(), &raw, sum)
		if err != nil {
			t.Fatal(err)
		}
		rebuilt, err := material.Rebuild(t.Context(), plan.ReconstructionSnapshots{Baseline: fw}, vendors.Renderer)
		if err != nil || rebuilt.Digest() != p.Digest() || rebuilt.After().SemanticDigest() != p.After().SemanticDigest() {
			t.Fatal("business reconstruction", err)
		}
		if _, err := rebuilt.Verify(t.Context(), p.After()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCoreReconstructionRequiresTheReplannedDigest(t *testing.T) {
	_, revision, p := finiteReconstructionPlan(t)
	var material bytes.Buffer
	if _, err := plan.EncodeReconstruction(t.Context(), &material, plan.SnapshotRevisions{Baseline: revision}, p); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(material.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	doc["plan_digest"] = strings.Repeat("0", 64)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	decoded, err := plan.DecodeReconstruction(t.Context(), bytes.NewReader(raw), hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal("well-formed material", err)
	}
	called := false
	rebuilt, err := decoded.Rebuild(t.Context(), plan.ReconstructionSnapshots{Baseline: p.Before()}, func(vendor string) (plan.Renderer, error) {
		called = true
		return vendors.Renderer(vendor)
	})
	if !errors.Is(err, plan.ErrReconstruction) || rebuilt != nil || !called {
		t.Fatal("material digest bypassed replanning", err, called)
	}
}

type reconstructionShortWriter struct{}

func (reconstructionShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestCoreReconstructionIOAndCancellation(t *testing.T) {
	_, revision, p := finiteReconstructionPlan(t)
	if _, err := plan.EncodeReconstruction(t.Context(), reconstructionShortWriter{}, plan.SnapshotRevisions{Baseline: revision}, p); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := plan.EncodeReconstruction(ctx, nil, plan.SnapshotRevisions{}, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := plan.DecodeReconstruction(ctx, nil, ""); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err := operations.RestorePlan(t.Context(), nil, revision, unusedRevisionLoader{}); !errors.Is(err, operations.ErrInvalid) {
		t.Fatal("nil-reader error", err)
	}
}

type unusedRevisionLoader struct{}

func (unusedRevisionLoader) Load(context.Context, string) (*fm.Firewall, error) {
	return nil, errors.New("must not load")
}

package operations_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
)

func migrationMaterialFixture(t *testing.T) (*batchFixture, plan.SnapshotRevisions, *plan.Plan) {
	t.Helper()
	fixture := newBatchFixture(t)
	device := fixture.report.Devices[0]
	data := device.Batch.Plan.After().Export()
	data.Metadata.Device = "migration-source"
	for n := range data.Rules {
		data.Rules[n].Log, data.Rules[n].LogStart, data.Rules[n].LogEnd = fm.Irrelevant, fm.Irrelevant, fm.Irrelevant
	}
	source, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := fixture.store.Publish(t.Context(), source, snapshot.PublishOptions{PublicationID: "migration-source"})
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := vendors.Renderer(device.Batch.Plan.Before().Metadata().Vendor)
	if err != nil {
		t.Fatal(err)
	}
	coordinate := plan.MigrationContext{Chain: fm.PolicyChain{RuleSet: "security"}, FromZone: "inside", ToZone: "outside"}
	p, err := (plan.Planner{Renderer: renderer}).Migrate(t.Context(), source, device.Batch.Plan.Before(), plan.MigrationInput{Contexts: []plan.MigrationContextMapping{{Source: coordinate, Target: coordinate}}})
	if err != nil {
		t.Fatal(err)
	}
	return fixture, plan.SnapshotRevisions{Baseline: device.Revision, Source: publication.Revision}, p
}

func TestMigrationReconstructionRequiresBothSnapshots(t *testing.T) {
	fixture, revisions, p := migrationMaterialFixture(t)
	var raw bytes.Buffer
	if _, err := plan.EncodeReconstruction(t.Context(), &raw, plan.SnapshotRevisions{Baseline: revisions.Baseline}, p); !errors.Is(err, plan.ErrReconstruction) || raw.Len() != 0 {
		t.Fatal("missing explicit source revision", err)
	}
	checksum, err := plan.EncodeReconstruction(t.Context(), &raw, revisions, p)
	if err != nil {
		t.Fatal(err)
	}
	material, err := plan.DecodeReconstruction(t.Context(), bytes.NewReader(raw.Bytes()), checksum)
	if err != nil || material.Revision() != revisions.Baseline || material.SourceRevision() != revisions.Source {
		t.Fatal("snapshot refs", err)
	}
	called := false
	selectRenderer := func(vendor string) (plan.Renderer, error) { called = true; return vendors.Renderer(vendor) }
	for _, snapshots := range []plan.ReconstructionSnapshots{{Baseline: p.Before()}, {Baseline: p.Before(), Source: p.Before()}, {Baseline: p.MigrationSource(), Source: p.Before()}} {
		got, err := material.Rebuild(t.Context(), snapshots, selectRenderer)
		if got != nil || !errors.Is(err, plan.ErrReconstruction) || called {
			t.Fatal("invalid source reached renderer", err, called)
		}
	}
	restored, revision, err := operations.RestorePlan(t.Context(), bytes.NewReader(raw.Bytes()), checksum, fixture.store)
	if err != nil || revision != revisions.Baseline || restored.Digest() != p.Digest() || restored.MigrationSource().SemanticDigest() != p.MigrationSource().SemanticDigest() {
		t.Fatal("dual snapshot reconstruction", err)
	}
	if _, err := restored.Verify(t.Context(), p.After()); err != nil {
		t.Fatal(err)
	}
	input, _ := restored.MigrationInput()
	original, _ := p.MigrationInput()
	if !reflect.DeepEqual(input, original) {
		t.Fatal("migration mappings changed")
	}
	// The ordinary durable selection path also has to retain the source revision.
	report := operations.BatchReport{Version: 1, Devices: []operations.DevicePlan{{Device: p.Before().Metadata().Device, Revision: revisions.Baseline, SemanticDigest: p.Before().SemanticDigest(), Batch: plan.BatchResult{Plan: p}}}}
	selection := operations.Selection{Device: p.Before().Metadata().Device, Revision: revisions.Baseline, SourceRevision: revisions.Source, PlanDigest: p.Digest()}
	prepared, err := fixture.executor(t).Prepare(t.Context(), "migration", report, []operations.Selection{selection})
	if err != nil || len(prepared.Selections) != 1 || prepared.Selections[0] != selection {
		t.Fatal("migration selection", err)
	}
}

func TestReconstructionRejectsChangedIntentEvenWithNewChecksum(t *testing.T) {
	_, revisions, p := migrationMaterialFixture(t)
	var raw bytes.Buffer
	if _, err := plan.EncodeReconstruction(t.Context(), &raw, revisions, p); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"legacy-version", "source-metadata", "mapping", "mixed-kind", "budget"} {
		t.Run(mode, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(raw.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "legacy-version":
				doc["version"] = 1
			case "source-metadata":
				doc["source"].(map[string]any)["metadata"].(map[string]any)["Context"] = "changed"
			case "mapping":
				doc["migration"].(map[string]any)["Contexts"].([]any)[0].(map[string]any)["Target"].(map[string]any)["FromZone"] = "missing"
			case "mixed-kind":
				doc["mode"] = "preserve"
			case "budget":
				doc["options"].(map[string]any)["Limits"].(map[string]any)["MaxVisits"] = 1
				doc["migration"].(map[string]any)["Rules"] = []string{"a", "b"}
			}
			changed, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(changed)
			material, err := plan.DecodeReconstruction(t.Context(), bytes.NewReader(changed), hex.EncodeToString(digest[:]))
			if err == nil {
				_, err = material.Rebuild(t.Context(), plan.ReconstructionSnapshots{Baseline: p.Before(), Source: p.MigrationSource()}, vendors.Renderer)
			}
			if err == nil {
				t.Fatal("tampered intent became approved plan")
			}
		})
	}
}

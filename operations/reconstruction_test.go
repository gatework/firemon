package operations_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
	"strings"
	"testing"
	"time"
)

func TestPlanReconstructionPinsOriginalInputsAndOptions(t *testing.T) {
	_, store, _, req := collectionFixture(t)
	before, err := store.Load(t.Context(), req.Expected)
	if err != nil {
		t.Fatal(err)
	}
	renderer, _ := vendors.Renderer("paloalto")
	limits := policy.Limits{MaxVisits: 200000, MaxRegions: 256, MaxCombinations: 1024}
	planner := plan.Planner{Renderer: renderer, MaxCandidates: 13, Engine: policy.Engine{Limits: limits}}
	q := policy.Request{Traffic: requestTraffic(t, "192.0.2.10/32", "198.51.100.10/32", 443), FromZone: "inside", ToZone: "outside"}
	bad := q
	bad.FromZone = "missing"
	result, err := planner.PlanBatch(t.Context(), before, []policy.Request{bad, q})
	if err != nil || result.Plan == nil {
		t.Fatal(result, err)
	}
	if result.Plan.BatchOptions().MaxCandidates != 13 || result.Plan.BatchOptions().Limits != limits {
		t.Fatal("options lost")
	}
	var data bytes.Buffer
	checksum, err := operations.EncodePlan(t.Context(), &data, req.Expected, result.Plan)
	if err != nil {
		t.Fatal(err)
	}
	restored, revision, err := operations.RestorePlan(t.Context(), bytes.NewReader(data.Bytes()), checksum, store)
	if err != nil || revision != req.Expected || restored.Digest() != result.Plan.Digest() || len(restored.InputRequests()) != 2 || restored.BatchOptions() != result.Plan.BatchOptions() {
		t.Fatal(revision, err)
	}
	var document map[string]any
	if err = json.Unmarshal(data.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"version", "algorithm", "plan_digest", "baseline_revision"} {
		copy := map[string]any{}
		for k, v := range document {
			copy[k] = v
		}
		copy[key] = "tampered"
		raw, _ := json.Marshal(copy)
		if _, _, e := operations.RestorePlan(t.Context(), bytes.NewReader(raw), checksum, store); e == nil {
			t.Fatal("tampered", key)
		}
	}
	if _, _, err = operations.RestorePlan(t.Context(), strings.NewReader(data.String()+" {}"), checksum, store); err == nil {
		t.Fatal("trailing accepted")
	}
}

func TestFiniteBusinessPacketPlanReconstruction(t *testing.T) {
	const raw = "zone inside\nexit\nzone outside\nexit\ninterface eth0\nzone inside\nip address 192.0.2.1/24\nexit\ninterface eth1\nzone outside\nip address 198.51.100.1/24\nexit\n"
	m := fm.Metadata{Device: "finite", Vendor: "hillstone", Software: "5.5R8", CapturedAt: time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)}
	sum := sha256.Sum256([]byte(raw))
	clock := fm.ScheduleClock{Device: m.Device, Vendor: m.Vendor, Software: m.Software, CapturedAt: m.CapturedAt, SourceDigest: hex.EncodeToString(sum[:]), Timezone: "Asia/Hong_Kong", Reference: "synthetic independent clock", EndBoundary: "exclusive", TickSeconds: 1}
	fw, err := (vendors.Parser{}).Parse(t.Context(), config.Source{Text: raw, Complete: true, ScheduleClock: &clock}, m)
	if err != nil {
		t.Fatal(err)
	}
	store, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, err := store.Publish(t.Context(), fw, snapshot.PublishOptions{PublicationID: "finite"})
	if err != nil {
		t.Fatal(err)
	}
	w := fm.TimeWindow{Start: m.CapturedAt.Add(2 * time.Hour), End: m.CapturedAt.Add(3 * time.Hour)}
	input := operations.AccessRequest{ID: "temporary", Traffic: requestTraffic(t, "192.0.2.10/32", "198.51.100.10/32", 443), Targets: []operations.AccessTarget{{Device: m.Device, Packet: true, Request: policy.Request{FromZone: "inside", ToZone: "outside"}}}, Native: &operations.NativeEffects{Lifetime: &plan.ScheduleIntent{Schedule: "temporary", Window: w, Clock: clock}, Additions: plan.NativeAdditions{Schedules: []fm.ScheduleRecord{{Object: fm.Object{ID: "temporary", Name: "temporary"}, Windows: []fm.TimeWindow{w}, Timezone: clock.Timezone}}}}}
	d, err := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	report, err := d.Design(t.Context(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{input}})
	if err != nil || len(report.Devices) != 1 || report.Devices[0].Batch.Plan == nil {
		t.Fatalf("finite business packet plan: %+v %v", report, err)
	}
	p := report.Devices[0].Batch.Plan
	if !report.Inputs[0].Request.At.IsZero() {
		t.Fatal("original input time changed")
	}
	var b bytes.Buffer
	checksum, err := operations.EncodePlan(t.Context(), &b, pub.Revision, p)
	if err != nil {
		t.Fatal(err)
	}
	restored, _, err := operations.RestorePlan(t.Context(), &b, checksum, store)
	if err != nil || restored.Digest() != p.Digest() || len(restored.NativeInputs()) != 1 || restored.NativeInputs()[0].Lifetime == nil || len(restored.PacketProofs()) != 1 {
		t.Fatal("native reconstruction lost lifetime/packet", err)
	}
}

type reconstructionLoader struct {
	operations.RevisionLoader
	loads int
}

func (l *reconstructionLoader) Load(ctx context.Context, revision string) (*fm.Firewall, error) {
	l.loads++
	return l.RevisionLoader.Load(ctx, revision)
}
func TestReconstructionStrictAndBudgetChecksBeforeSnapshotLoad(t *testing.T) {
	_, store, _, req := collectionFixture(t)
	fw, _ := store.Load(t.Context(), req.Expected)
	renderer, _ := vendors.Renderer("paloalto")
	r, err := (plan.Planner{Renderer: renderer}).PlanBatch(t.Context(), fw, []policy.Request{{Traffic: requestTraffic(t, "192.0.2.10/32", "198.51.100.10/32", 443), FromZone: "inside", ToZone: "outside"}})
	if err != nil || r.Plan == nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	_, err = operations.EncodePlan(t.Context(), &b, req.Expected, r.Plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"version", "algorithm", "unknown", "trailing", "size", "options", "budget", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "version":
				doc["version"] = 9
			case "algorithm":
				doc["algorithm"] = "latest"
			case "unknown":
				doc["unexpected"] = true
			case "options":
				doc["options"].(map[string]any)["MaxCandidates"] = 1000000000
			case "budget":
				doc["options"].(map[string]any)["Limits"].(map[string]any)["MaxVisits"] = 1
				doc["policy"] = []any{doc["policy"].([]any)[0], doc["policy"].([]any)[0]}
			}
			raw, _ := json.Marshal(doc)
			if mode == "trailing" {
				raw = append(raw, []byte(" {}")...)
			}
			if mode == "size" {
				raw = bytes.Repeat([]byte(" "), operations.MaxRequestBytes+1)
			}
			sum := sha256.Sum256(raw)
			loader := &reconstructionLoader{RevisionLoader: store}
			ctx := t.Context()
			if mode == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			_, _, err := operations.RestorePlan(ctx, bytes.NewReader(raw), hex.EncodeToString(sum[:]), loader)
			if err == nil || loader.loads != 0 {
				t.Fatal("validation after snapshot access", err, loader.loads)
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}
func TestBusinessReportDocumentOwnsNestedContainers(t *testing.T) {
	scope, vrf := "s", "v"
	r := operations.BatchReport{Topology: &inventory.Topology{Version: 1, Bindings: []inventory.Binding{{Sources: []string{"origin"}}}}, Inputs: []operations.RequestOutcome{{Request: operations.AccessRequest{Scope: &scope, VRF: &vrf, Sources: []string{"ticket"}, Native: &operations.NativeEffects{Lifetime: &plan.ScheduleIntent{Schedule: "temporary"}, Additions: plan.NativeAdditions{Schedules: []fm.ScheduleRecord{{Object: fm.Object{ID: "temporary"}, Recurring: []string{"opaque"}}}}}}, Outcomes: []operations.TargetOutcome{{Sources: []string{"path"}, NAT: policy.NATRelation{Steps: []policy.NATStep{{ID: "n"}}}}}}}, Issues: []operations.Issue{{Sources: []string{"issue"}}}, Devices: []operations.DevicePlan{{Batch: plan.BatchResult{Inputs: []plan.BatchInput{{Attempts: []plan.BatchAttempt{{Reason: "reject"}}}}}}}}
	doc := r.Document()
	doc.Topology.Bindings[0].Sources[0] = "changed"
	*doc.Inputs[0].Request.Scope = "changed"
	*doc.Inputs[0].Request.VRF = "changed"
	doc.Inputs[0].Request.Sources[0] = "changed"
	doc.Inputs[0].Request.Native.Lifetime.Schedule = "changed"
	doc.Inputs[0].Request.Native.Additions.Schedules[0].Recurring[0] = "changed"
	doc.Inputs[0].Outcomes[0].Sources[0] = "changed"
	doc.Inputs[0].Outcomes[0].NAT.Steps[0].ID = "changed"
	doc.Issues[0].Sources[0] = "changed"
	doc.Devices[0].Inputs[0].Attempts[0].Reason = "changed"
	if r.Topology.Bindings[0].Sources[0] != "origin" || scope != "s" || vrf != "v" || r.Inputs[0].Request.Sources[0] != "ticket" || r.Inputs[0].Request.Native.Lifetime.Schedule != "temporary" || r.Inputs[0].Request.Native.Additions.Schedules[0].Recurring[0] != "opaque" || r.Inputs[0].Outcomes[0].Sources[0] != "path" || r.Inputs[0].Outcomes[0].NAT.Steps[0].ID != "n" || r.Issues[0].Sources[0] != "issue" || r.Devices[0].Batch.Inputs[0].Attempts[0].Reason != "reject" {
		t.Fatal("report alias escaped")
	}
}

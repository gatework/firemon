package operations_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
)

func TestIntentMaterialDeterminismAndRoundTrip(t *testing.T) {
	b := newBatchFixture(t)
	executor := b.executor(t)
	prepared, err := executor.Prepare(t.Context(), "intent-material", b.report, b.selections)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := executor.Prepare(t.Context(), "intent-material", b.report, b.selections)
	if err != nil || !reflect.DeepEqual(prepared, repeated) {
		t.Fatal("selection not deterministic", err)
	}
	raw, err := json.Marshal(b.report.Document())
	if err != nil {
		t.Fatal(err)
	}
	var report operations.ReportDocument
	if err := json.Unmarshal(raw, &report); err != nil || !reflect.DeepEqual(report, prepared.Review) {
		t.Fatal("review roundtrip", err)
	}
	files, err := filepath.Glob(filepath.Join(b.root, "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	raw, err = os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != prepared.Digest {
		t.Fatal("selection digest does not bind persisted bytes")
	}
	store, revision, finite := finiteReconstructionPlan(t)
	for _, tc := range []struct {
		name, revision string
		p              *plan.Plan
		store          *snapshot.Store
	}{{"policy", b.report.Devices[0].Revision, b.report.Devices[0].Batch.Plan, b.store}, {"finite", revision, finite, store}} {
		t.Run(tc.name, func(t *testing.T) {
			var first, second bytes.Buffer
			digest, err := plan.EncodeReconstruction(t.Context(), &first, plan.SnapshotRevisions{Baseline: tc.revision}, tc.p)
			if err != nil {
				t.Fatal(err)
			}
			again, err := plan.EncodeReconstruction(t.Context(), &second, plan.SnapshotRevisions{Baseline: tc.revision}, tc.p)
			if err != nil || digest != again || !bytes.Equal(first.Bytes(), second.Bytes()) {
				t.Fatal("reconstruction not deterministic", err)
			}
			p, rev, err := operations.RestorePlan(t.Context(), &first, digest, tc.store)
			if err != nil || rev != tc.revision || p.Digest() != tc.p.Digest() || p.After().SemanticDigest() != tc.p.After().SemanticDigest() {
				t.Fatal("reconstruction changed semantics", rev, err)
			}
		})
	}
}

func finiteReconstructionPlan(t testing.TB) (*snapshot.Store, string, *plan.Plan) {
	t.Helper()
	const raw = "zone inside\nexit\nzone outside\nexit\ninterface eth0\nzone inside\nip address 192.0.2.1/24\nexit\ninterface eth1\nzone outside\nip address 198.51.100.1/24\nexit\n"
	m := fm.Metadata{Device: "finite", Vendor: "hillstone", Software: "5.5R8", CapturedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}
	sum := sha256.Sum256([]byte(raw))
	clock := fm.ScheduleClock{Device: m.Device, Vendor: m.Vendor, Software: m.Software, CapturedAt: m.CapturedAt, SourceDigest: hex.EncodeToString(sum[:]), Timezone: "Asia/Hong_Kong", Reference: "synthetic clock", EndBoundary: "exclusive", TickSeconds: 1}
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
	w := fm.TimeWindow{Start: m.CapturedAt.Add(time.Hour), End: m.CapturedAt.Add(2 * time.Hour)}
	src, _ := flow.PrefixRange(netip.MustParsePrefix("192.0.2.10/32"))
	dst, _ := flow.PrefixRange(netip.MustParsePrefix("198.51.100.10/32"))
	traffic, err := flow.NewTraffic(32, flow.TrafficRegion{Source: src, Destination: dst, Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{High: 65535}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
	if err != nil {
		t.Fatal(err)
	}
	q := policy.Request{Traffic: traffic, FromZone: "inside", ToZone: "outside"}
	renderer, err := vendors.Renderer("hillstone")
	if err != nil {
		t.Fatal(err)
	}
	in := plan.NativeRequest{Request: q, Packet: &policy.PacketRequest{Request: q}, Sources: []string{"ticket", "finite"}, Lifetime: &plan.ScheduleIntent{Schedule: "temporary", Window: w, Clock: clock}, Additions: plan.NativeAdditions{Schedules: []fm.ScheduleRecord{{Object: fm.Object{ID: "temporary", Name: "temporary"}, Windows: []fm.TimeWindow{w}, Timezone: clock.Timezone}}}}
	result, err := (plan.Planner{Renderer: renderer, NativeRenderer: renderer.(plan.NativeRenderer)}).PlanNativeBatch(t.Context(), fw, []plan.NativeRequest{in})
	if err != nil || result.Plan == nil {
		t.Fatal(result, err)
	}
	return store, pub.Revision, result.Plan
}

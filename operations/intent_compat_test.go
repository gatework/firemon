package operations_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
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

func TestIntentMaterialCompatibility(t *testing.T) {
	b := newBatchFixture(t)
	executor := b.executor(t)
	prepared, err := executor.Prepare(t.Context(), "intent-compat", b.report, b.selections)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(b.report.Document())
	if err != nil {
		t.Fatal(err)
	}
	assertMaterialGolden(t, "report.json", raw)
	files, err := filepath.Glob(filepath.Join(b.root, "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	raw, err = os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	assertMaterialGolden(t, "selection.json", raw)
	assertMaterialGolden(t, "selection.sha256", []byte(prepared.Digest+"\n"))
	store, revision, finite := finiteCompatibilityPlan(t)
	for _, tc := range []struct {
		name, revision string
		p              *plan.Plan
		store          *snapshot.Store
	}{
		{"policy", b.report.Devices[0].Revision, b.report.Devices[0].Batch.Plan, b.store},
		{"finite", revision, finite, store},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var material bytes.Buffer
			sum, err := operations.EncodePlan(t.Context(), &material, tc.revision, tc.p)
			if err != nil {
				t.Fatal(err)
			}
			assertMaterialGolden(t, tc.name+".json", material.Bytes())
			assertMaterialGolden(t, tc.name+".sha256", []byte(sum+"\n"))
			p, rev, err := operations.RestorePlan(t.Context(), &material, sum, tc.store)
			if err != nil || rev != tc.revision || p.Digest() != tc.p.Digest() {
				t.Fatal(rev, err)
			}
		})
	}
}

func finiteCompatibilityPlan(t testing.TB) (*snapshot.Store, string, *plan.Plan) {
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

func assertMaterialGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "intent-compat", name)
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("persisted bytes changed: %s", name)
	}
}

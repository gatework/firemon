package vendors_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
	"strings"
	"testing"
	"time"
)

func scheduleCapture(t *testing.T, vendor, version, raw string, clock bool) (*fm.Firewall, fm.ScheduleClock) {
	t.Helper()
	m := fm.Metadata{CapturedAt: time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC), Device: "synthetic-time", Vendor: vendor, Software: version}
	if vendor == "fortinet" {
		m.Context = "root"
	}
	sum := sha256.Sum256([]byte(raw))
	m.SourceDigest = hex.EncodeToString(sum[:])
	c := fm.ScheduleClock{CapturedAt: m.CapturedAt, Device: m.Device, Vendor: m.Vendor, Software: m.Software, Context: m.Context, SourceDigest: m.SourceDigest, Timezone: "Asia/Hong_Kong", Reference: "synthetic clock/endpoint observation", EndBoundary: "exclusive", TickSeconds: 1}
	source := config.Source{Text: raw, Complete: true}
	if clock {
		source.ScheduleClock = &c
	}
	fw, err := (vendors.Parser{}).Parse(t.Context(), source, m)
	if err != nil {
		t.Fatal(err)
	}
	return fw, c
}
func scheduleCases() []struct{ vendor, version, raw string } {
	return []struct{ vendor, version, raw string }{
		{"hillstone", "5.5R8", "schedule temporary\nabsolute start 10/31/2026 10:00 end 10/31/2026 11:00\nexit\n"},
		{"fortinet", "7.2.8", "config firewall schedule onetime\nedit temporary\nset start 10:00 2026/10/31\nset end 11:00 2026/10/31\nnext\nend\n"},
		{"huawei", "V500R005", "time-range temporary\n absolute-range 10:00:00 2026/10/31 to 11:00:00 2026/10/31\n#\n"},
		{"netscreen", "6.3.0", "set scheduler temporary once start 10/31/2026 10:00 stop 10/31/2026 11:00\n"},
	}
}
func TestAbsoluteNativeScheduleCapture(t *testing.T) {
	start := time.Date(2026, 10, 31, 2, 0, 0, 0, time.UTC)
	for _, tc := range scheduleCases() {
		t.Run(tc.vendor, func(t *testing.T) {
			fw, _ := scheduleCapture(t, tc.vendor, tc.version, tc.raw, true)
			s := fw.Schedule("temporary")
			if !fw.Complete() || s == nil || s.HasUnsupported() || s.Record().Timezone != "Asia/Hong_Kong" {
				t.Fatalf("unknown native schedule: %#v %v", s, fw.Diagnostics())
			}
			for _, at := range []time.Time{start.Add(-time.Nanosecond), start, start.Add(time.Hour - time.Nanosecond), start.Add(time.Hour)} {
				active, known := s.ActiveAt(at)
				want := !at.Before(start) && at.Before(start.Add(time.Hour))
				if !known || active != want {
					t.Fatal(at, active, known)
				}
			}
			unknown, _ := scheduleCapture(t, tc.vendor, tc.version, tc.raw, false)
			if s := unknown.Schedule("temporary"); s != nil {
				if _, known := s.ActiveAt(start); known {
					t.Fatal("missing clock became known")
				}
			}
		})
	}
}

func TestTemporaryNativePlan(t *testing.T) {
	start := time.Date(2026, 10, 31, 2, 0, 0, 0, time.UTC)
	for _, tc := range scheduleCases() {
		t.Run(tc.vendor, func(t *testing.T) {
			var baseRaw string
			for _, n := range nativeCases() {
				if n.vendor == tc.vendor {
					baseRaw = n.before
					break
				}
			}
			rules := map[string]string{
				"hillstone": "policy-global\nrule id 10\nsrc-zone inside\ndst-zone outside\nsrc-addr any\ndst-addr any\nservice any\nschedule temporary\naction permit\nexit\nexit\n",
				"fortinet":  "config firewall policy\nedit 10\nset name temporary-policy\nset srcintf lan1\nset dstintf wan1\nset srcaddr all\nset dstaddr all\nset service ALL\nset schedule temporary\nset action accept\nset logtraffic disable\nnext\nend\n",
				"huawei":    "security-policy\n rule name temporary-policy\n  source-zone trust\n  destination-zone untrust\n  time-range temporary\n  action permit\n#\n",
				"netscreen": "set policy id 10 from Trust to Untrust Any Any ANY permit schedule temporary\nexit\n",
			}
			before, clock := scheduleCapture(t, tc.vendor, tc.version, baseRaw, true)
			after, _ := scheduleCapture(t, tc.vendor, tc.version, baseRaw+tc.raw+rules[tc.vendor], true)
			if !after.Complete() {
				t.Fatal(after.Diagnostics())
			}
			c := nativeDelta(before, after)
			c.Additions.Schedules = []fm.ScheduleRecord{after.Schedule("temporary").Record()}
			for i := range c.Additions.Rules {
				c.Additions.Rules[i].Position = -1
			}
			q := policy.Request{RuleSet: "security", At: start}
			switch tc.vendor {
			case "hillstone":
				q.FromZone, q.ToZone = "inside", "outside"
			case "fortinet":
				q.Scope, q.FromZone, q.ToZone = "root", "lan1", "wan1"
			case "huawei":
				q.FromZone, q.ToZone = "trust", "untrust"
			case "netscreen":
				q.FromZone, q.ToZone = "Trust", "Untrust"
			}
			all, _ := flow.AllTraffic(4096)
			q.Traffic = all
			known, err := (policy.Engine{}).Query(t.Context(), after, q)
			if err != nil || !known.Complete || known.Allowed.Empty() {
				t.Fatal(known, err)
			}
			q.Traffic = known.Allowed
			lifetime := &plan.ScheduleIntent{Schedule: "temporary", Window: fm.TimeWindow{Start: start, End: start.Add(time.Hour)}, Clock: clock}
			input := plan.NativeRequest{Request: q, Additions: c.Additions, Lifetime: lifetime}
			renderer, _ := vendors.Renderer(tc.vendor)
			planner := plan.Planner{Renderer: renderer, NativeRenderer: renderer.(plan.NativeRenderer)}
			result, err := planner.PlanNativeBatch(t.Context(), before, []plan.NativeRequest{input})
			if err != nil || result.Plan == nil {
				t.Fatalf("temporary plan: %+v %v", result, err)
			}
			if result.Version != 3 {
				t.Fatal("finite intent must have its own approval version")
			}
			if _, err = result.Plan.Verify(t.Context(), after); err != nil {
				t.Fatal("independent readback", err)
			}
			commands := strings.Join(result.Plan.Commands(), "\n")
			if !strings.Contains(commands, "temporary") {
				t.Fatal(commands)
			}
			var encoded bytes.Buffer
			if err = snapshot.Encode(&encoded, result.Plan.After()); err != nil {
				t.Fatal(err)
			}
			restored, err := snapshot.Decode(&encoded, snapshot.DefaultMaxBytes)
			if err != nil {
				t.Fatal(err)
			}
			for _, at := range []time.Time{start.Add(-time.Second), start, start.Add(time.Hour - time.Nanosecond), start.Add(time.Hour)} {
				q.At = at
				v, e := (policy.Engine{}).Query(t.Context(), restored, q)
				if e != nil || !v.Complete || !v.Unknown.Empty() || v.Allowed.Empty() == (!at.Before(start) && at.Before(start.Add(time.Hour))) {
					t.Fatal(at, v, e)
				}
			}
			reusedBefore, reusedClock := scheduleCapture(t, tc.vendor, tc.version, baseRaw+tc.raw, true)
			reuse := input.Clone()
			reuse.Additions.Schedules = nil
			reuse.Lifetime.Clock = reusedClock
			reused, e := planner.PlanNativeBatch(t.Context(), reusedBefore, []plan.NativeRequest{reuse})
			if e != nil || reused.Plan == nil || len(reused.Plan.NativeChanges().Additions.Schedules) != 0 {
				t.Fatal("existing schedule reuse", reused, e)
			}
			if _, e = reused.Plan.Verify(t.Context(), after); e != nil {
				t.Fatal(e)
			}
			badClock := clock
			badClock.SourceDigest = strings.Repeat("0", 64)
			if _, e = (vendors.Parser{}).Parse(t.Context(), config.Source{Text: baseRaw + tc.raw, Complete: true, ScheduleClock: &badClock}, after.Metadata()); e == nil {
				t.Fatal("reused baseline clock accepted for independent capture")
			}
			bad := input.Clone()
			bad.Lifetime.Window.End = bad.Lifetime.Window.End.Add(-time.Minute)
			rejected, e := planner.PlanNativeBatch(t.Context(), before, []plan.NativeRequest{bad})
			if e != nil || rejected.Plan != nil {
				t.Fatal("mismatched window accepted", rejected, e)
			}
			bad = input.Clone()
			bad.Lifetime = nil
			rejected, e = planner.PlanNativeBatch(t.Context(), before, []plan.NativeRequest{bad})
			if e != nil || rejected.Plan != nil {
				t.Fatal("scheduled declaration without finite intent", rejected, e)
			}
			unknown, _ := scheduleCapture(t, tc.vendor, tc.version, baseRaw+tc.raw+rules[tc.vendor], false)
			if _, err = result.Plan.Verify(t.Context(), unknown); err == nil {
				t.Fatal("readback with missing clock accepted")
			}
		})
	}
}

func TestTemporaryPolicyOwnedNAT(t *testing.T) {
	start := time.Date(2026, 10, 31, 2, 0, 0, 0, time.UTC)
	for _, name := range []string{"fortinet-source-pool", "netscreen-dip-owner"} {
		t.Run(name, func(t *testing.T) {
			var tc nativeCase
			for _, v := range nativeCases() {
				if v.name == name {
					tc = v
					break
				}
			}
			if tc.vendor == "" {
				t.Fatal("fixture missing")
			}
			var schedule string
			for _, s := range scheduleCases() {
				if s.vendor == tc.vendor {
					schedule = s.raw
				}
			}
			raw := strings.ReplaceAll(tc.after, "set schedule always", "set schedule temporary")
			if tc.vendor == "netscreen" {
				raw = strings.ReplaceAll(raw, " permit\n", " permit schedule temporary\n")
			}
			before, clock := scheduleCapture(t, tc.vendor, tc.version, tc.before, true)
			after, _ := scheduleCapture(t, tc.vendor, tc.version, tc.before+schedule+raw, true)
			if !after.Complete() {
				t.Fatal(after.Diagnostics())
			}
			c := nativeDelta(before, after)
			c.Additions.Schedules = []fm.ScheduleRecord{after.Schedule("temporary").Record()}
			for i := range c.Additions.Rules {
				c.Additions.Rules[i].Position = -1
			}
			all, _ := flow.AllTraffic(4096)
			q := policy.Request{Scope: tc.scope, RuleSet: "security", FromZone: fm.ID(tc.from), ToZone: fm.ID(tc.to), EgressInterface: fm.ID(tc.egress), At: start, Traffic: all}
			covered, e := (policy.Engine{}).Query(t.Context(), after, q)
			if e != nil {
				t.Fatal(e)
			}
			q.Traffic = covered.Allowed
			contexts, e := (policy.Engine{}).NATContexts(t.Context(), start, before, after)
			if e != nil {
				t.Fatal(e)
			}
			var intents []policy.NATIntent
			for _, nq := range contexts {
				if !nq.At.Equal(start) {
					continue
				}
				nq.Traffic = all
				r, e := (policy.Engine{}).QueryNAT(t.Context(), after, nq)
				if e != nil {
					t.Fatal(e)
				}
				for _, rel := range r.Relations {
					nq.Traffic = rel.Original
					intents = append(intents, policy.NATIntent{Request: nq, Steps: rel.Steps})
				}
			}
			if len(intents) == 0 {
				t.Fatal("no active translation")
			}
			in := plan.NativeRequest{Request: q, Additions: c.Additions, NAT: intents, Lifetime: &plan.ScheduleIntent{Schedule: "temporary", Clock: clock, Window: fm.TimeWindow{Start: start, End: start.Add(time.Hour)}}}
			renderer, _ := vendors.Renderer(tc.vendor)
			planner := plan.Planner{NativeRenderer: renderer.(plan.NativeRenderer)}
			result, e := planner.PlanNativeBatch(t.Context(), before, []plan.NativeRequest{in})
			if e != nil || result.Plan == nil {
				t.Fatal(result, e)
			}
			if _, e = result.Plan.Verify(t.Context(), after); e != nil {
				t.Fatal(e)
			}
			leaking := in.Clone()
			leaking.Additions.DynamicNATs[0].Match.Schedule = ""
			// Even when a declaration differs only in time, it must match native owner
			// semantics and the outside-time relation proof; no permanence exemption.
			bad, e := planner.PlanNativeBatch(t.Context(), before, []plan.NativeRequest{leaking})
			if e != nil || bad.Plan != nil {
				t.Fatal("NAT outside lifetime accepted", bad, e)
			}
		})
	}
}

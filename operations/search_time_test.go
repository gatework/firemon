package operations_test

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
)

func searchTimeRange(t *testing.T, prefix string) flow.AddressRange {
	t.Helper()
	r, err := flow.PrefixRange(netip.MustParsePrefix(prefix))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func searchTimeMatch(schedule fm.ID) fm.Match {
	return fm.Match{Schedule: schedule, AnySource: true, AnyDestination: true,
		AnyService: true, AnyFromZone: true, AnyToZone: true}
}

func searchTimeData() fm.Data {
	return fm.Data{
		Metadata: fm.Metadata{Device: "query-time", Vendor: "hillstone"},
		Zones:    []fm.ZoneRecord{{Object: fm.Object{ID: "inside"}}, {Object: fm.Object{ID: "outside"}}},
	}
}

func publishSearchTime(t *testing.T, data fm.Data) (*countedBatchStore, string) {
	t.Helper()
	fw, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	store, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, err := store.Publish(t.Context(), fw, snapshot.PublishOptions{PublicationID: "query-time", Live: true})
	if err != nil {
		t.Fatal(err)
	}
	return &countedBatchStore{Store: store}, pub.Revision
}

func searchTimeRequest() operations.AccessRequest {
	return operations.AccessRequest{
		Src: "192.0.2.1", Dst: "198.51.100.1", Service: "443",
		Targets: []operations.AccessTarget{{Device: "query-time", Request: policy.Request{FromZone: "inside", ToZone: "outside"}}},
	}
}

func searchRule(t *testing.T, outcome operations.TargetOutcome, id fm.ID) operations.RuleMatch {
	t.Helper()
	for _, match := range outcome.Matches {
		if match.Rule == id {
			return match
		}
	}
	t.Fatalf("missing declaration %s: %+v", id, outcome.Matches)
	return operations.RuleMatch{}
}

func TestSearcherReevaluatesPointTimeForCachedRevision(t *testing.T) {
	start := time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)
	window := fm.TimeWindow{Start: start, End: start.Add(time.Hour)}
	data := searchTimeData()
	data.Schedules = []fm.ScheduleRecord{{Object: fm.Object{ID: "temporary"}, Timezone: "UTC", Windows: []fm.TimeWindow{window}}}
	data.Rules = []fm.RuleRecord{
		{Object: fm.Object{ID: "scheduled"}, RuleSet: "security", Action: fm.Permit, Match: searchTimeMatch("temporary")},
		{Object: fm.Object{ID: "fallback"}, RuleSet: "security", Position: 1, Action: fm.Deny, Match: searchTimeMatch("")},
	}
	store, revision := publishSearchTime(t, data)
	var now time.Time
	searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	request := searchTimeRequest()
	for _, tc := range []struct {
		at    time.Time
		state string
		allow bool
	}{{start.Add(-time.Nanosecond), "not_started", false}, {start, "active", true}, {window.End, "expired", false}} {
		now = tc.at
		report, err := searcher.Query(t.Context(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{request}})
		if err != nil || len(report.Inputs) != 1 || len(report.Inputs[0].Outcomes) != 1 {
			t.Fatal(report, err)
		}
		o := report.Inputs[0].Outcomes[0]
		if o.Revision != revision || !o.At.Equal(tc.at) || o.Window != nil || !o.Policy.Complete {
			t.Fatal("query cached a prior time decision", o, tc)
		}
		if o.Policy.Allowed.Empty() == tc.allow || o.Policy.Denied.Empty() != tc.allow {
			t.Fatal("query did not honor half-open admission", o.Policy, tc)
		}
		m := searchRule(t, o, "scheduled")
		if m.ScheduleState != tc.state || len(m.Declared) == 0 || (len(m.Effective) != 0) != tc.allow ||
			!m.DeclaredKnown || !m.EffectiveKnown || !slices.Equal(m.Windows, []fm.TimeWindow{window}) {
			t.Fatal("rule declaration and current effectiveness were conflated", m, tc)
		}
	}
	if store.loads != 1 || store.manifests != 3 || !request.At.IsZero() {
		t.Fatal("graph was reloaded or input time was mutated", store.loads, store.manifests, request.At)
	}
}

func TestSearcherWindowReportsExactIntervalsAndUnknownSchedules(t *testing.T) {
	start := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	data := searchTimeData()
	data.Schedules = []fm.ScheduleRecord{
		{Object: fm.Object{ID: "expired"}, Windows: []fm.TimeWindow{{Start: start.Add(-3 * time.Hour), End: start.Add(-2 * time.Hour)}}},
		{Object: fm.Object{ID: "temporary"}, Windows: []fm.TimeWindow{{Start: start.Add(time.Hour), End: start.Add(2 * time.Hour)}}},
		{Object: fm.Object{ID: "future"}, Windows: []fm.TimeWindow{{Start: start.Add(3 * time.Hour), End: start.Add(4 * time.Hour)}}},
		{Object: fm.Object{ID: "unknown"}, Weekly: []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{{Day: time.Monday, End: time.Hour}}}}},
	}
	data.Addresses = []fm.AddressRecord{{Object: fm.Object{ID: "uncertain-source"}, Ranges: []flow.AddressRange{searchTimeRange(t, "192.0.2.1/32")}}}
	unknown := searchTimeMatch("unknown")
	unknown.AnySource = false
	unknown.Sources = []fm.AddressRef{{Kind: fm.AddressObject, ID: "uncertain-source"}}
	data.Rules = []fm.RuleRecord{
		{Object: fm.Object{ID: "old-permit"}, RuleSet: "security", Action: fm.Permit, Match: searchTimeMatch("expired")},
		{Object: fm.Object{ID: "temporary-permit"}, RuleSet: "security", Position: 1, Action: fm.Permit, Match: searchTimeMatch("temporary")},
		{Object: fm.Object{ID: "future-permit"}, RuleSet: "security", Position: 2, Action: fm.Permit, Match: searchTimeMatch("future")},
		{Object: fm.Object{ID: "unknown-permit"}, RuleSet: "security", Position: 3, Action: fm.Permit, Match: unknown},
		{Object: fm.Object{ID: "fallback"}, RuleSet: "security", Position: 4, Action: fm.Deny, Match: searchTimeMatch("")},
	}
	store, _ := publishSearchTime(t, data)
	searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	request := searchTimeRequest()
	request.Src = "192.0.2.1,192.0.2.3"
	request.Window = &fm.TimeWindow{Start: start, End: start.Add(5 * time.Hour)}
	report, err := searcher.Query(t.Context(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{request}})
	if err != nil || len(report.Inputs) != 1 || len(report.Inputs[0].Outcomes) != 5 {
		t.Fatal("query omitted chronological repeats or rejected unknown evidence", report, err)
	}
	for i, outcome := range report.Inputs[0].Outcomes {
		want := fm.TimeWindow{Start: start.Add(time.Duration(i) * time.Hour), End: start.Add(time.Duration(i+1) * time.Hour)}
		if outcome.Window == nil || *outcome.Window != want || !outcome.At.Equal(want.Start) || !outcome.Conditional {
			t.Fatal("window is not the exact chronological partition", outcome, want)
		}
		old := searchRule(t, outcome, "old-permit")
		uncertain := searchRule(t, outcome, "unknown-permit")
		if old.ScheduleState != "expired" || len(old.Declared) == 0 || len(old.Effective) != 0 || uncertain.ScheduleState != "unknown" {
			t.Fatal("expired or missing clock evidence was hidden", old, uncertain)
		}
		temporary := searchRule(t, outcome, "temporary-permit")
		future := searchRule(t, outcome, "future-permit")
		if temporary.ScheduleState != []string{"not_started", "active", "expired", "expired", "expired"}[i] ||
			future.ScheduleState != []string{"not_started", "not_started", "not_started", "active", "expired"}[i] {
			t.Fatal("future and expired declarations were confused", temporary, future)
		}
		if i == 1 || i == 3 {
			if !outcome.Policy.Complete || outcome.Policy.Allowed.Empty() || !outcome.Policy.Unknown.Empty() || len(uncertain.Effective) != 0 {
				t.Fatal("known earlier permit lost first-match precedence", outcome)
			}
		} else if outcome.Policy.Complete || !outcome.Policy.Allowed.Empty() || outcome.Policy.Unknown.Empty() || outcome.Policy.Denied.Empty() || uncertain.EffectiveKnown {
			t.Fatal("unknown schedule became a certain permit or suppressed unrelated deny", outcome)
		}
	}
	if store.loads != 1 {
		t.Fatal("window reparsed or reloaded the same revision", store.loads)
	}
	// A certain denied fraction is useful query evidence, but an incomplete
	// capture must never become a source for new policy changes.
	designer, err := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	request.Window, request.At, request.Src = nil, start, "192.0.2.3"
	design, err := designer.Design(t.Context(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{request}})
	if err != nil || len(design.Devices) != 0 || len(design.Inputs) != 1 || len(design.Inputs[0].Outcomes) != 1 {
		t.Fatal("incomplete snapshot was admitted for policy changes", design, err)
	}
	if !design.Inputs[0].Outcomes[0].Conditional || design.Inputs[0].Outcomes[0].Policy.Denied.Empty() {
		t.Fatal("incomplete source lost its evidence boundary", design)
	}
}

func TestSearcherDistinguishesDeclaredAndFirstMatchTraffic(t *testing.T) {
	data := searchTimeData()
	data.Addresses = []fm.AddressRecord{{Object: fm.Object{ID: "blocked"}, Ranges: []flow.AddressRange{searchTimeRange(t, "192.0.2.1/32")}}}
	deny := searchTimeMatch("")
	deny.AnySource = false
	deny.Sources = []fm.AddressRef{{Kind: fm.AddressObject, ID: "blocked"}}
	data.Rules = []fm.RuleRecord{
		{Object: fm.Object{ID: "deny-first"}, RuleSet: "security", Action: fm.Deny, Match: deny},
		{Object: fm.Object{ID: "permit-later"}, RuleSet: "security", Position: 1, Action: fm.Permit, Match: searchTimeMatch("")},
		{Object: fm.Object{ID: "disabled"}, RuleSet: "security", Position: 2, Action: fm.Deny, Disabled: true, Match: searchTimeMatch("")},
	}
	store, _ := publishSearchTime(t, data)
	searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	request := searchTimeRequest()
	request.Src = "192.0.2.0/30"
	report, err := searcher.Query(t.Context(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{request}})
	if err != nil || len(report.Inputs) != 1 || len(report.Inputs[0].Outcomes) != 1 {
		t.Fatal(report, err)
	}
	o := report.Inputs[0].Outcomes[0]
	later := searchRule(t, o, "permit-later")
	disabled := searchRule(t, o, "disabled")
	declared, err := flow.NewTraffic(16, later.Declared...)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := flow.NewTraffic(16, later.Effective...)
	if err != nil {
		t.Fatal(err)
	}
	region := requestTraffic(t, "192.0.2.0/30", "198.51.100.1/32", 443).Regions()[0]
	region.SourcePort = flow.Interval{High: 65535}
	whole, err := flow.NewTraffic(16, region)
	if err != nil {
		t.Fatal(err)
	}
	region.Source = searchTimeRange(t, "192.0.2.1/32")
	blocked, err := flow.NewTraffic(16, region)
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := whole.Difference(blocked, 16)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ got, want flow.Traffic }{{declared, whole}, {effective, remaining}} {
		if equal, err := tc.got.Equal(tc.want, 16); err != nil || !equal {
			t.Fatal("declaration was reported as effective first-match coverage", tc, err)
		}
	}
	if !disabled.Disabled || len(disabled.Declared) == 0 || len(disabled.Effective) != 0 || !disabled.EffectiveKnown {
		t.Fatal("disabled declaration was omitted or treated as effective", disabled)
	}
}

func TestFiniteSimpleDesignRequiresCaptureClockAndExplicitService(t *testing.T) {
	const raw = "zone inside\nexit\nzone outside\nexit\ninterface eth0\nzone inside\nip address 192.0.2.1/24\nexit\ninterface eth1\nzone outside\nip address 198.51.100.1/24\nexit\n"
	metadata := fm.Metadata{Device: "query-time", Vendor: "hillstone", Software: "5.5R8", CapturedAt: time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)}
	digest := sha256.Sum256([]byte(raw))
	clock := fm.ScheduleClock{
		Device: metadata.Device, Vendor: metadata.Vendor, Software: metadata.Software, CapturedAt: metadata.CapturedAt,
		SourceDigest: hex.EncodeToString(digest[:]), Timezone: "Asia/Hong_Kong", Reference: "synthetic independently observed clock",
		EndBoundary: "exclusive", TickSeconds: 1,
	}
	fw, err := (vendors.Parser{}).Parse(t.Context(), config.Source{Text: raw, Complete: true, ScheduleClock: &clock}, metadata)
	if err != nil {
		t.Fatal(err)
	}
	store, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Publish(t.Context(), fw, snapshot.PublishOptions{PublicationID: "finite-input"}); err != nil {
		t.Fatal(err)
	}
	window := fm.TimeWindow{Start: metadata.CapturedAt.Add(2 * time.Hour), End: metadata.CapturedAt.Add(3 * time.Hour)}
	input := searchTimeRequest()
	input.Window = &window
	for _, tc := range []struct {
		name, service, issue string
		clock                *fm.ScheduleClock
	}{
		{name: "missing clock", service: "443", issue: "clock_required"},
		{name: "different capture", service: "443", issue: "clock_required", clock: func() *fm.ScheduleClock { c := clock; c.SourceDigest = strings.Repeat("0", 64); return &c }()},
		{name: "omitted service", issue: "service_required", clock: &clock},
		{name: "clipboard empty service", service: "\ufeff\" \t \"", issue: "service_required", clock: &clock},
		{name: "punctuation-only service", service: ";,", issue: "invalid_input", clock: &clock},
		{name: "bound finite policy", service: "443", clock: &clock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := operations.BatchDesignerOptions{Store: store}
			if tc.clock != nil {
				options.Clocks = map[string]fm.ScheduleClock{metadata.Device: *tc.clock}
			}
			designer, err := operations.NewBatchDesigner(options)
			if err != nil {
				t.Fatal(err)
			}
			request := input
			request.Service = tc.service
			report, err := designer.Design(t.Context(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{request}})
			if err != nil {
				t.Fatal(report, err)
			}
			if tc.issue != "" {
				found := false
				for _, issue := range report.Issues {
					found = found || issue.Code == tc.issue
				}
				for _, device := range report.Devices {
					if device.Batch.Plan != nil {
						t.Fatal("missing evidence yielded an executable policy", tc.name, device.Batch.Plan)
					}
				}
				if !found {
					t.Fatal("missing reason for withheld plan", tc.issue, report)
				}
				return
			}
			if len(report.Devices) != 1 || report.Devices[0].Batch.Plan == nil {
				t.Fatal("finite input with clock evidence was not designed", report)
			}
			p := report.Devices[0].Batch.Plan
			native := p.NativeInputs()
			if len(native) != 1 || native[0].Lifetime == nil || native[0].Lifetime.Window != window || native[0].Lifetime.Clock != clock {
				t.Fatal("finite input lost its capture-bound lifetime", native)
			}
			q := policy.Request{Traffic: requestTraffic(t, input.Src+"/32", input.Dst+"/32", 443), FromZone: "inside", ToZone: "outside"}
			for _, at := range []time.Time{window.Start.Add(-time.Second), window.Start, window.End.Add(-time.Second), window.End} {
				q.At = at
				result, err := (policy.Engine{}).Query(t.Context(), p.After(), q)
				allowed := !at.Before(window.Start) && at.Before(window.End)
				if err != nil || !result.Complete || result.Allowed.Empty() == allowed {
					t.Fatal("finite design became unrestricted outside its lifetime", at, result, err)
				}
			}
		})
	}
}

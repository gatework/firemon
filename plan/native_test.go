package plan_test

import (
	"context"
	"errors"
	"runtime"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

type nativeRenderer struct{}

func (nativeRenderer) RenderNative(ctx context.Context, before, after *fm.Firewall, changes plan.NativeChanges) ([]string, error) {
	if err := plan.ValidateNativeChanges(ctx, before, after, changes); err != nil {
		return nil, err
	}
	return []string{"synthetic complete typed change"}, nil
}
func nativeInput(t *testing.T) plan.NativeRequest {
	q := request(t, "192.0.2.2/32")
	n := fm.StaticNATRecord{Object: fm.Object{ID: "fixed", Name: "fixed"}, Match: fm.Match{AnySource: true, Destinations: []fm.AddressRef{{Kind: fm.AddressObject, ID: "dst"}}, Services: []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "https"}}, AnyFromZone: true, AnyToZone: true}, Source: []fm.Mapping{{Original: addressRange("192.0.2.2/32"), Translated: addressRange("203.0.113.2/32"), Mode: fm.Offset}}}
	return plan.NativeRequest{Request: q, Additions: plan.NativeAdditions{StaticNATs: []fm.StaticNATRecord{n}}, NAT: []policy.NATIntent{{Request: q, Steps: []policy.NATStep{{Kind: fm.StaticNATObject, ID: "fixed"}}}}}
}
func TestNativePlanAtomicNATAndPolicyReadback(t *testing.T) {
	input := nativeInput(t)
	result, err := (plan.Planner{NativeRenderer: nativeRenderer{}}).PlanNativeBatch(context.Background(), baseline(t), []plan.NativeRequest{input})
	if err != nil || result.Plan == nil {
		t.Fatal(result, err)
	}
	p := result.Plan
	if result.Inputs[0].Disposition != plan.BatchAccepted || p.After().StaticNAT("fixed") == nil || p.Proof().NATUnchanged || p.NATProof() == nil {
		t.Fatal("missing joint proof", result)
	}
	if _, err = p.Verify(context.Background(), p.After()); err != nil {
		t.Fatal(err)
	}
	bad := p.After().Export()
	bad.StaticNATs[0].Source[0].Mode = fm.Constant
	observed, _ := fm.Seal(bad)
	if _, err = p.Verify(context.Background(), observed); err == nil {
		t.Fatal("mapping mode change accepted")
	}
	original := p.NativeInputs()
	original[0].Additions.StaticNATs[0].Source[0].Mode = fm.Constant
	if p.NativeInputs()[0].Additions.StaticNATs[0].Source[0].Mode != fm.Offset {
		t.Fatal("intent ownership escaped")
	}
}
func TestNativePlanRejectedInputLeavesNoNAT(t *testing.T) {
	input := nativeInput(t)
	input.NAT[0].Steps[0].ID = "missing"
	good := plan.NativeRequest{Request: request(t, "192.0.2.3/32")}
	result, err := (plan.Planner{NativeRenderer: nativeRenderer{}}).PlanNativeBatch(context.Background(), baseline(t), []plan.NativeRequest{input, good})
	if err != nil || result.Plan == nil {
		t.Fatal(result, err)
	}
	if result.Inputs[0].Disposition != plan.BatchRejected || result.Plan.After().StaticNATCount() != 0 || len(result.Plan.NativeInputs()) != 2 {
		t.Fatal("rejected input leaked", result)
	}
}

func TestNativeReadbackMapsTypedCreatedIdentities(t *testing.T) {
	in := nativeInput(t)
	result, err := (plan.Planner{NativeRenderer: nativeRenderer{}}).PlanNativeBatch(context.Background(), baseline(t), []plan.NativeRequest{in})
	if err != nil || result.Plan == nil {
		t.Fatal(result, err)
	}
	data := result.Plan.After().Export()
	data.StaticNATs[0].ID = "allocated-42"
	observed, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := result.Plan.Verify(context.Background(), observed)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.CreatedIDs()[plan.NativeIdentity{Kind: plan.NativeStaticNAT, ID: "fixed"}] != "allocated-42" {
		t.Fatal("missing typed mapping", receipt.CreatedIDs())
	}
}
func TestNativeIntentRejectsUnrequestedOutsideAndPriorNoNAT(t *testing.T) {
	for _, test := range []string{"outside", "no-nat"} {
		t.Run(test, func(t *testing.T) {
			in := nativeInput(t)
			base := baseline(t)
			if test == "outside" {
				in.Additions.StaticNATs[0].Match.AnyService = true
				in.Additions.StaticNATs[0].Match.Services = nil
			} else {
				d := base.Export()
				d.DynamicNATs = []fm.DynamicNATRecord{{Object: fm.Object{ID: "exempt"}, Match: in.Additions.StaticNATs[0].Match, Order: fm.NATOrder{Section: "snat", Position: -1}, SourceMode: fm.NoTranslation, DestinationMode: fm.NoTranslation}}
				base, _ = fm.Seal(d)
			}
			result, err := (plan.Planner{NativeRenderer: nativeRenderer{}}).PlanNativeBatch(context.Background(), base, []plan.NativeRequest{in})
			if err != nil {
				t.Fatal(err)
			}
			if result.Plan != nil || result.Inputs[0].Disposition != plan.BatchRejected {
				t.Fatal("unsafe nat accepted", result)
			}
		})
	}
}

func TestNativePlanPoolPossibilitiesAndOwnerAtomicity(t *testing.T) {
	in := nativeInput(t)
	in.Additions.StaticNATs = nil
	in.Additions.Addresses = []fm.AddressRecord{{Object: fm.Object{ID: "original", Name: "original"}, Ranges: []flow.AddressRange{addressRange("192.0.2.2/32")}}}
	m := fm.Match{Sources: []fm.AddressRef{{Kind: fm.AddressObject, ID: "original"}}, Destinations: []fm.AddressRef{{Kind: fm.AddressObject, ID: "dst"}}, Services: []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "https"}}, AnyFromZone: true, AnyToZone: true}
	in.Additions.NATPools = []fm.NATPoolRecord{{Object: fm.Object{ID: "pool", Name: "pool"}, Ranges: []flow.AddressRange{addressRange("203.0.113.0/30")}}}
	in.Additions.DynamicNATs = []fm.DynamicNATRecord{{Object: fm.Object{ID: "allocate", Name: "allocate"}, Match: m, Order: fm.NATOrder{Section: "snat"}, SourceMode: fm.DynamicIP, DestinationMode: fm.NoTranslation, SourcePool: "pool"}}
	in.NAT[0].Steps = []policy.NATStep{{Kind: fm.DynamicNATObject, ID: "allocate"}}
	result, err := (plan.Planner{NativeRenderer: nativeRenderer{}}).PlanNativeBatch(context.Background(), baseline(t), []plan.NativeRequest{in})
	if err != nil || result.Plan == nil {
		t.Fatal(result, err)
	}
	got, err := (policy.Engine{}).QueryNAT(context.Background(), result.Plan.After(), in.Request)
	if err != nil || len(got.Relations) != 1 || !got.Relations[0].PossibleAllocation || got.Relations[0].Exact {
		t.Fatal(got, err)
	}
	if got.Relations[0].Translated.Regions()[0].Source != addressRange("203.0.113.0/30") {
		t.Fatal("pool became single observed allocation")
	}
	// A new NAT declaration cannot silently attach to an old policy owner.
	in.Additions.DynamicNATs[0].Rule = "10"
	refused, err := (plan.Planner{NativeRenderer: nativeRenderer{}}).PlanNativeBatch(context.Background(), baseline(t), []plan.NativeRequest{in})
	if err != nil || refused.Plan != nil {
		t.Fatal(refused, err)
	}
}
func TestNativePlanRejectsOrphanTypedAdditions(t *testing.T) {
	in := nativeInput(t)
	in.Additions.NATPools = []fm.NATPoolRecord{{Object: fm.Object{ID: "orphan"}, Ranges: []flow.AddressRange{addressRange("203.0.113.0/24")}}}
	result, err := (plan.Planner{NativeRenderer: nativeRenderer{}}).PlanNativeBatch(context.Background(), baseline(t), []plan.NativeRequest{in})
	if err != nil {
		t.Fatal(err)
	}
	if result.Plan != nil {
		t.Fatal("unowned pool accepted")
	}
}

func TestNativePlanFixedOffsetPortsAndExplicitReverse(t *testing.T) {
	in := nativeInput(t)
	original := in.Request.Traffic.Regions()[0]
	original.SourcePort = flow.Interval{Low: 1000, High: 1000}
	in.Request.Traffic, _ = flow.NewTraffic(32, original)
	in.NAT[0].Request = in.Request
	in.Additions.Services = []fm.ServiceRecord{{Object: fm.Object{ID: "nat-service", Name: "nat-service"}, Terms: []fm.ServiceTerm{{Protocol: original.Protocol, SourcePort: original.SourcePort, DestinationPort: original.DestinationPort, ICMPType: original.ICMPType, ICMPCode: original.ICMPCode}}}}
	d := baseline(t).Export()
	d.Metadata.Vendor = "asa"
	d.Metadata.Software = "9.16(4)"
	base, _ := fm.Seal(d)
	n := &in.Additions.StaticNATs[0]
	n.Order = fm.NATOrder{Stage: 1, Section: "manual"}
	n.Bidirectional = true
	n.Match.Services = []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "nat-service"}}
	n.SourcePorts = []fm.PortMapping{{Original: flow.Interval{Low: 1000, High: 1000}, Translated: flow.Interval{Low: 2000, High: 2000}, Mode: fm.Offset}}
	reverse := in.Request
	box := reverse.Traffic.Regions()[0]
	box.Source, box.Destination = box.Destination, addressRange("203.0.113.2/32")
	box.SourcePort, box.DestinationPort = box.DestinationPort, box.SourcePort
	box.DestinationPort = flow.Interval{Low: 2000, High: 2000}
	reverse.Traffic, _ = flow.NewTraffic(32, box)
	planner := plan.Planner{NativeRenderer: nativeRenderer{}}
	refused, err := planner.PlanNativeBatch(context.Background(), base, []plan.NativeRequest{in})
	if err != nil || refused.Plan != nil {
		t.Fatal("implicit reverse was not requested", refused, err)
	}
	in.NAT = append(in.NAT, policy.NATIntent{Request: reverse, Steps: []policy.NATStep{{Kind: fm.StaticNATObject, ID: "fixed", Reverse: true}}})
	result, err := planner.PlanNativeBatch(context.Background(), base, []plan.NativeRequest{in})
	if err != nil || result.Plan == nil {
		t.Fatal(result, err)
	}
	mapped, err := (policy.Engine{}).QueryNAT(context.Background(), result.Plan.After(), reverse)
	if err != nil || len(mapped.Relations) != 1 || mapped.Relations[0].Translated.Regions()[0].Destination != addressRange("192.0.2.2/32") || mapped.Relations[0].Translated.Regions()[0].DestinationPort != (flow.Interval{Low: 1000, High: 1000}) {
		t.Fatal(mapped, err)
	}
	d.Metadata.Software = "unknown"
	base, _ = fm.Seal(d)
	refused, err = planner.PlanNativeBatch(context.Background(), base, []plan.NativeRequest{in})
	if err != nil || refused.Plan != nil {
		t.Fatal("unknown firmware accepted", refused, err)
	}
}
func TestNativePlanNewPolicyOwnerAndTypedReadback(t *testing.T) {
	for _, vendor := range []string{"netscreen", "fortinet"} {
		t.Run(vendor, func(t *testing.T) {
			in := nativeInput(t)
			m := in.Additions.StaticNATs[0].Match
			m.AnySource = false
			m.Sources = []fm.AddressRef{{Kind: fm.AddressObject, ID: "original"}}
			in.Additions.StaticNATs = nil
			d := baseline(t).Export()
			d.Metadata.Vendor = vendor
			base, _ := fm.Seal(d)
			in.Additions.Addresses = []fm.AddressRecord{{Object: fm.Object{ID: "original", Name: "original"}, Ranges: []flow.AddressRange{addressRange("192.0.2.2/32")}}}
			in.Additions.Rules = []fm.RuleRecord{{Object: fm.Object{ID: "owner", Name: "owner"}, RuleSet: "security", Position: -1, Action: fm.Permit, Log: fm.Irrelevant, Match: m}}
			in.Additions.NATPools = []fm.NATPoolRecord{{Object: fm.Object{ID: "pool", Name: "pool"}, Ranges: []flow.AddressRange{addressRange("203.0.113.0/30")}}}
			in.Additions.DynamicNATs = []fm.DynamicNATRecord{{Object: fm.Object{ID: "nat", Name: "nat"}, Rule: "owner", Match: m, Order: fm.NATOrder{Section: "policy"}, SourceMode: fm.DynamicIP, DestinationMode: fm.NoTranslation, SourcePool: "pool"}}
			in.NAT[0].Steps = []policy.NATStep{{Kind: fm.DynamicNATObject, ID: "nat"}}
			result, err := (plan.Planner{NativeRenderer: nativeRenderer{}}).PlanNativeBatch(context.Background(), base, []plan.NativeRequest{in})
			if err != nil || result.Plan == nil {
				t.Fatal(result, err)
			}
			observed := result.Plan.After().Export()
			for i := range observed.Rules {
				if observed.Rules[i].ID == "owner" {
					observed.Rules[i].ID = "200"
				}
			}
			observed.DynamicNATs[0].Rule = "200"
			observed.DynamicNATs[0].ID = "nat200"
			observed.NATPools[0].ID = "pool200"
			observed.DynamicNATs[0].SourcePool = "pool200"
			fw, err := fm.Seal(observed)
			if err != nil {
				t.Fatal(err)
			}
			readback, err := result.Plan.Verify(context.Background(), fw)
			if err != nil || readback.RuleIDs()["owner"] != "200" || readback.CreatedIDs()[plan.NativeIdentity{Kind: plan.NativePool, ID: "pool"}] != "pool200" {
				t.Fatal(readback, err)
			}
		})
	}
}

func TestNativePlanRejectsCrossTypedNATNameCollision(t *testing.T) {
	in := nativeInput(t)
	d := baseline(t).Export()
	d.DynamicNATs = []fm.DynamicNATRecord{{Object: fm.Object{ID: "other", Name: "fixed"}, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}, Disabled: true, SourceMode: fm.NoTranslation, DestinationMode: fm.NoTranslation}}
	base, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	result, err := (plan.Planner{NativeRenderer: nativeRenderer{}}).PlanNativeBatch(context.Background(), base, []plan.NativeRequest{in})
	if err != nil {
		t.Fatal(err)
	}
	if result.Plan != nil {
		t.Fatal("native NAT namespace collision accepted")
	}
}

func TestNativeApprovalReconstructionPreservesOptionsAndRejectedInputs(t *testing.T) {
	good := nativeInput(t)
	bad := good.Clone()
	bad.NAT[0].Steps[0].ID = "missing"
	planner := plan.Planner{NativeRenderer: nativeRenderer{}, MaxCandidates: 7, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 50000}}}
	first, err := planner.PlanNativeBatch(context.Background(), baseline(t), []plan.NativeRequest{bad, good})
	if err != nil || first.Plan == nil {
		t.Fatal(first, err)
	}
	options := first.Plan.NativeOptions()
	if options.MaxCandidates != 7 || options.Limits.MaxVisits != 50000 {
		t.Fatal(options)
	}
	rebuilt, err := (plan.Planner{NativeRenderer: nativeRenderer{}, MaxCandidates: options.MaxCandidates, Engine: policy.Engine{Limits: options.Limits}}).PlanNativeBatch(context.Background(), first.Plan.Before(), first.Plan.NativeInputs())
	if err != nil || rebuilt.Plan == nil || rebuilt.Plan.Digest() != first.Plan.Digest() {
		t.Fatal("native approval cannot be reconstructed", rebuilt, err)
	}
}

func TestNativeEquivalentDeclarationReuseNeedsNoCommands(t *testing.T) {
	in := nativeInput(t)
	first, err := (plan.Planner{NativeRenderer: nativeRenderer{}}).PlanNativeBatch(context.Background(), baseline(t), []plan.NativeRequest{in})
	if err != nil || first.Plan == nil {
		t.Fatal(first, err)
	}
	reused, err := (plan.Planner{}).PlanNativeBatch(context.Background(), first.Plan.After(), []plan.NativeRequest{in})
	if err != nil || reused.Plan == nil {
		t.Fatal(reused, err)
	}
	if reused.Inputs[0].Disposition != plan.BatchCovered || len(reused.Plan.Commands()) != 0 || reused.Plan.After().StaticNATCount() != 1 {
		t.Fatal("equivalent declaration was recreated", reused)
	}
}

func TestNativeIngressBoundsNestedContainersBeforeSemanticWork(t *testing.T) {
	const oversized = 65
	cases := map[string]func(*plan.NativeRequest){
		"address ranges": func(r *plan.NativeRequest) {
			r.Additions.Addresses = []fm.AddressRecord{{Ranges: make([]flow.AddressRange, oversized)}}
		},
		"service terms": func(r *plan.NativeRequest) {
			r.Additions.Services = []fm.ServiceRecord{{Terms: make([]fm.ServiceTerm, oversized)}}
		},
		"sources": func(r *plan.NativeRequest) { r.Sources = make([]string, oversized) },
		"packet regions": func(r *plan.NativeRequest) {
			r.Packet = &policy.PacketRequest{Request: policy.Request{Traffic: nativeBudgetTraffic(t, oversized)}}
		},
	}
	matches := map[string]func(*fm.Match){
		"sources":      func(m *fm.Match) { m.Sources = make([]fm.AddressRef, oversized) },
		"destinations": func(m *fm.Match) { m.Destinations = make([]fm.AddressRef, oversized) },
		"services":     func(m *fm.Match) { m.Services = make([]fm.ServiceRef, oversized) },
		"from zones":   func(m *fm.Match) { m.FromZones = make([]fm.ID, oversized) },
		"to zones":     func(m *fm.Match) { m.ToZones = make([]fm.ID, oversized) },
		"applications": func(m *fm.Match) { m.Applications = make([]string, oversized) },
		"users":        func(m *fm.Match) { m.Users = make([]string, oversized) },
		"unsupported":  func(m *fm.Match) { m.Unsupported = make([]string, oversized) },
	}
	for name, set := range matches {
		for _, kind := range []string{"rule", "static", "dynamic"} {
			cases[kind+" match "+name] = func(r *plan.NativeRequest) {
				var m fm.Match
				set(&m)
				switch kind {
				case "rule":
					r.Additions.Rules = []fm.RuleRecord{{Match: m}}
				case "static":
					r.Additions.StaticNATs = []fm.StaticNATRecord{{Match: m}}
				case "dynamic":
					r.Additions.DynamicNATs = []fm.DynamicNATRecord{{Match: m}}
				}
			}
		}
	}
	for _, kind := range []string{"rule", "address", "service", "static", "dynamic", "pool"} {
		for _, field := range []string{"spans", "unsupported"} {
			cases[kind+" object "+field] = func(r *plan.NativeRequest) {
				var o fm.Object
				if field == "spans" {
					o.Spans = make([]fm.Span, oversized)
				} else {
					o.Unsupported = make([]string, oversized)
				}
				switch kind {
				case "rule":
					r.Additions.Rules = []fm.RuleRecord{{Object: o}}
				case "address":
					r.Additions.Addresses = []fm.AddressRecord{{Object: o}}
				case "service":
					r.Additions.Services = []fm.ServiceRecord{{Object: o}}
				case "static":
					r.Additions.StaticNATs = []fm.StaticNATRecord{{Object: o}}
				case "dynamic":
					r.Additions.DynamicNATs = []fm.DynamicNATRecord{{Object: o}}
				case "pool":
					r.Additions.NATPools = []fm.NATPoolRecord{{Object: o}}
				}
			}
		}
	}
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := plan.NativeRequest{}
			mutate(&r)
			result, err := (plan.Planner{Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 64}}}).PlanNativeBatch(context.Background(), fw, []plan.NativeRequest{r})
			if !errors.Is(err, policy.ErrBudget) || result.Plan != nil {
				t.Fatalf("oversized input reached semantic rejection or planning: %v %+v", err, result)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := (plan.Planner{}).PlanNativeBatch(ctx, fw, []plan.NativeRequest{{Sources: make([]string, oversized)}})
	if !errors.Is(err, context.Canceled) || result.Plan != nil {
		t.Fatal(result, err)
	}
}
func nativeBudgetTraffic(t *testing.T, count int) flow.Traffic {
	t.Helper()
	box := request(t, "192.0.2.2/32").Traffic.Regions()[0]
	regions := make([]flow.TrafficRegion, count)
	for i := range regions {
		regions[i] = box
		regions[i].SourcePort = flow.Interval{Low: uint16(i * 2), High: uint16(i * 2)}
	}
	traffic, err := flow.NewTraffic(count+1, regions...)
	if err != nil || traffic.RegionCount() != count {
		t.Fatal(traffic.RegionCount(), err)
	}
	return traffic
}

type nativeCancelCheckpoint struct {
	context.Context
	checks, limit int
}

func (c *nativeCancelCheckpoint) Err() error {
	c.checks++
	if c.checks >= c.limit {
		return context.Canceled
	}
	return nil
}
func TestNativeIngressCancellationDuringNestedPreflight(t *testing.T) {
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := &nativeCancelCheckpoint{Context: context.Background(), limit: 16}
	input := plan.NativeRequest{Additions: plan.NativeAdditions{Addresses: make([]fm.AddressRecord, 8)}}
	result, err := (plan.Planner{Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 100}}}).PlanNativeBatch(ctx, fw, []plan.NativeRequest{input})
	if !errors.Is(err, context.Canceled) || result.Plan != nil {
		t.Fatal(result, err)
	}
}
func TestNativeIngressRejectsBeforeCopyingNestedRanges(t *testing.T) {
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}})
	if err != nil {
		t.Fatal(err)
	}
	inputs := []plan.NativeRequest{{Additions: plan.NativeAdditions{Addresses: []fm.AddressRecord{{Ranges: make([]flow.AddressRange, 8192)}}}}}
	planner := plan.Planner{Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 8}}}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 5 {
		result, err := planner.PlanNativeBatch(context.Background(), fw, inputs)
		if !errors.Is(err, policy.ErrBudget) || result.Plan != nil {
			t.Fatal(result, err)
		}
	}
	runtime.ReadMemStats(&after)
	if bytes := (after.TotalAlloc - before.TotalAlloc) / 5; bytes > 64<<10 {
		t.Fatalf("rejection copied oversized nested ranges: %d bytes/call", bytes)
	}
}

func TestNativeIngressSharesCapacityAcrossInputs(t *testing.T) {
	inputs := []plan.NativeRequest{{Sources: make([]string, 32)}, {Sources: make([]string, 32)}}
	if err := plan.PreflightNativeRequests(context.Background(), inputs, policy.Limits{MaxVisits: 64}); !errors.Is(err, policy.ErrBudget) {
		t.Fatal("per-input reset escaped aggregate capacity", err)
	}
	// Positive capacity is consumed exactly; exhaustion must not restore defaults.
	if err := plan.PreflightNativeRequests(context.Background(), []plan.NativeRequest{{Sources: make([]string, 63)}}, policy.Limits{MaxVisits: 64}); err != nil {
		t.Fatal(err)
	}
}

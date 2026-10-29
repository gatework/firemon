package analysis_test

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

func TestOrderedPolicyAgainstPacketOracle(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		packets := oraclePackets(ipv6)
		first, last := packets[0], packets[len(packets)-1]
		whole := oraclePoint(first)
		whole.Source.Last, whole.Destination.Last = last.source, last.destination
		whole.Protocol.High, whole.SourcePort.High, whole.DestinationPort.High, whole.ICMPType.High, whole.ICMPCode.High = 17, 1, 1, 1, 1
		at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		for _, scenario := range []string{"earlier deny", "unknown match", "disabled", "schedule start", "schedule end", "unknown schedule", "position tie", "multiple coverage", "paired service"} {
			t.Run(fmt.Sprintf("ipv6=%v/%s", ipv6, scenario), func(t *testing.T) {
				data := fm.Data{Metadata: fm.Metadata{Device: "oracle", Vendor: "hillstone"}, Rules: []fm.RuleRecord{oracleRule("early", 0, fm.Deny), oracleRule("later", 1, fm.Permit)}}
				early := &data.Rules[0]
				early.Match.AnySource = false
				early.Match.Sources = []fm.AddressRef{{Kind: fm.AddressObject, ID: "source"}}
				data.Addresses = []fm.AddressRecord{{Object: fm.Object{ID: "source"}, Ranges: []flow.AddressRange{{First: first.source, Last: first.source}}}}
				queryAt := at
				switch scenario {
				case "unknown match":
					early.Match.Unsupported = []string{"unresolved application"}
				case "disabled":
					early.Disabled = true
				case "schedule start", "schedule end", "unknown schedule":
					early.Match.Schedule = "window"
					data.Schedules = []fm.ScheduleRecord{{Object: fm.Object{ID: "window"}, Windows: []fm.TimeWindow{{Start: at, End: at.Add(time.Hour)}}}}
					if scenario == "schedule end" {
						queryAt = at.Add(time.Hour)
					}
					if scenario == "unknown schedule" {
						queryAt = time.Time{}
					}
				case "position tie":
					data.Rules[1].Position = 0
					slices.Reverse(data.Rules)
				case "multiple coverage":
					early.Action = fm.Permit
				case "paired service":
					early.Match.AnyService = false
					early.Match.Services = []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "paired"}}
					data.Services = []fm.ServiceRecord{{Object: fm.Object{ID: "paired"}, Terms: []fm.ServiceTerm{
						{Protocol: flow.Interval{Low: 0, High: 0}, SourcePort: flow.Interval{High: 1}, DestinationPort: flow.Interval{}, ICMPType: flow.Interval{High: 1}, ICMPCode: flow.Interval{High: 1}},
						{Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 1, High: 1}, DestinationPort: flow.Interval{Low: 1, High: 1}, ICMPType: flow.Interval{High: 1}, ICMPCode: flow.Interval{High: 1}},
					}}}
				}
				result, err := (policy.Engine{}).Query(context.Background(), oracleSeal(t, data), policy.Request{Traffic: oracleMakeTraffic(t, whole), At: queryAt})
				if err != nil {
					t.Fatal(err)
				}
				wantComplete := true
				for _, packet := range packets {
					want := oracleEvaluate(t, data, packet, queryAt)
					if !want.known {
						wantComplete = false
					}
					matches := 0
					for class, traffic := range map[string]flow.Traffic{"allowed": result.Allowed, "denied": result.Denied, "unknown": result.Unknown, "unmatched": result.Unmatched} {
						if oracleTraffic(traffic, packet) {
							matches++
							if class != want.class {
								t.Fatalf("packet %+v: %s want %s", packet, class, want.class)
							}
						}
					}
					if matches != 1 {
						t.Fatalf("packet %+v belongs to %d partitions", packet, matches)
					}
					decisions := 0
					for _, decision := range result.Decisions {
						if !oracleTraffic(decision.Traffic, packet) {
							continue
						}
						decisions++
						if decision.Rule != want.rule || decision.Action != want.action || decision.Known != want.known {
							t.Fatalf("decision %+v want %+v", decision, want)
						}
					}
					if (decisions == 1) != (want.rule != "") {
						t.Fatalf("packet has %d decisions: %+v", decisions, want)
					}
				}
				if result.Complete != wantComplete {
					t.Fatalf("complete=%v want %v", result.Complete, wantComplete)
				}
			})
		}
	}
}

func TestRequestOptimizationAgainstPacketOracle(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		packets := oraclePackets(ipv6)
		for seed := range 16 {
			var requests []policy.Request
			var declared []flow.TrafficRegion
			for i := range 6 {
				region := oraclePoint(packets[(seed*79+i*97)%len(packets)])
				declared = append(declared, region)
				requests = append(requests, policy.Request{Traffic: oracleMakeTraffic(t, region)})
			}
			groups, err := (analysis.RequestOptimizer{}).Optimize(context.Background(), requests)
			if err != nil || len(groups) != 1 {
				t.Fatalf("groups=%d: %v", len(groups), err)
			}
			if !slices.Equal(groups[0].Inputs, []int{0, 1, 2, 3, 4, 5}) {
				t.Fatal("input provenance changed")
			}
			for _, packet := range packets {
				want := false
				for _, region := range declared {
					want = want || oracleRegion(region, packet)
				}
				if oracleTraffic(groups[0].Request.Traffic, packet) != want {
					t.Fatalf("optimization changed packet %+v", packet)
				}
			}
		}
	}
}

func assertOraclePreservation(t *testing.T, before, after *fm.Firewall, at time.Time, target *policy.Request, sameOwner bool) {
	t.Helper()
	beforeData, afterData := before.Export(), after.Export()
	for _, packet := range oraclePackets(false) {
		old, next := oracleEvaluate(t, beforeData, packet, at), oracleEvaluate(t, afterData, packet, at)
		if target != nil && oracleTraffic(target.Traffic, packet) {
			if next.class != "allowed" {
				t.Fatalf("target packet not allowed: %+v: %+v", packet, next)
			}
			continue
		}
		if !sameOwner {
			old.rule, next.rule = "", ""
		}
		if old != next {
			t.Fatalf("outside behavior changed for %+v: %+v -> %+v", packet, old, next)
		}
	}
}

func TestPlansAndLifecycleAgainstPacketOracle(t *testing.T) {
	ctx := context.Background()
	pairs := [][2]string{{"192.0.2.0", "192.0.3.0"}, {"192.0.2.1", "192.0.3.0"}, {"192.0.2.1", "192.0.3.1"}}
	planner := plan.Planner{Renderer: oracleRenderer{}}
	for _, scenario := range []string{"reuse", "append", "cross-pair", "deny between", "cost tie", "logging"} {
		t.Run(scenario, func(t *testing.T) {
			fw := graph(t, pairs[:1])
			targetPair := pairs[1]
			switch scenario {
			case "reuse":
				targetPair = pairs[0]
			case "cross-pair":
				targetPair = pairs[2]
			case "deny between":
				fw = graph(t, pairs)
				data := fw.Export()
				data.Rules[1].Action = fm.Deny
				fw = oracleSeal(t, data)
			case "cost tie":
				fw = graph(t, [][2]string{pairs[0], pairs[0]})
			case "logging":
				data := fw.Export()
				data.Rules[0].Log = fm.Known
				fw = oracleSeal(t, data)
			}
			packet := oraclePackets(false)[0]
			packet.source = netip.MustParseAddr(targetPair[0])
			packet.destination = netip.MustParseAddr(targetPair[1])
			region := oraclePoint(packet)
			region.Protocol = flow.Interval{High: 255}
			region.SourcePort, region.DestinationPort = flow.Interval{High: 65535}, flow.Interval{High: 65535}
			region.ICMPType, region.ICMPCode = flow.Interval{High: 255}, flow.Interval{High: 255}
			target := policy.Request{Traffic: oracleMakeTraffic(t, region)}
			candidate, err := planner.Plan(ctx, fw, []policy.Request{target})
			if err != nil {
				t.Fatal(err)
			}
			assertOraclePreservation(t, fw, candidate.After(), time.Time{}, &target, true)
			again, err := planner.Plan(ctx, fw, []policy.Request{target})
			if err != nil || candidate.Cost() != again.Cost() || candidate.Digest() != again.Digest() {
				t.Fatal("nondeterministic plan", err)
			}
		})
	}
	fw := graph(t, [][2]string{pairs[0], pairs[0], pairs[1]})
	candidates, err := (analysis.Converger{Planner: planner}).Candidates(ctx, fw, time.Time{})
	if err != nil || len(candidates) == 0 {
		t.Fatal(candidates, err)
	}
	for _, candidate := range candidates {
		if candidate.Plan != nil {
			assertOraclePreservation(t, fw, candidate.Plan.After(), time.Time{}, nil, false)
		}
	}
	data := fw.Export()
	disabled := oracleRule("4", 4, fm.Deny)
	disabled.Disabled = true
	data.Rules = append(data.Rules, disabled)
	fw = oracleSeal(t, data)
	reclaimer := analysis.Reclaimer{Planner: planner}
	rows, err := reclaimer.Analyze(ctx, fw, analysis.ReclamationRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var selected []fm.ID
	for _, row := range rows {
		if row.RemovalCandidate {
			selected = append(selected, row.Rule)
		}
	}
	if !slices.Contains(selected, fm.ID("2")) || !slices.Contains(selected, fm.ID("4")) {
		t.Fatal("missing unreachable/disabled candidates", selected)
	}
	reclaimed, err := reclaimer.Plan(ctx, fw, analysis.ReclamationRequest{}, selected)
	if err != nil {
		t.Fatal(err)
	}
	assertOraclePreservation(t, fw, reclaimed.After(), time.Time{}, nil, false)
	if len(reclaimed.After().Addresses()) != len(fw.Addresses()) {
		t.Fatal("removed shared address objects")
	}
}

// Native renderer syntax is exercised by vendor fixtures. This sink isolates
// the policy proof from command representability in the finite reference domain.
type oracleRenderer struct{}

func (oracleRenderer) Render(context.Context, *fm.Firewall, *fm.Firewall, []plan.Change) ([]string, error) {
	return []string{"synthetic proof test"}, nil
}

package benchmarks_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/huawei"
)

func host(i int) netip.Addr { return netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}) }

func traffic(tb testing.TB, box flow.Box) flow.Traffic {
	tb.Helper()
	v, err := flow.NewTraffic(4096, box)
	if err != nil {
		tb.Fatal(err)
	}
	return v
}

func request(tb testing.TB, i int, port uint16) policy.Request {
	tb.Helper()
	src, dst := host(i), netip.MustParseAddr("203.0.113.10")
	return policy.Request{FromZone: "inside", ToZone: "outside", Traffic: traffic(tb, flow.Box{
		Source: flow.Range{First: src, Last: src}, Destination: flow.Range{First: dst, Last: dst},
		Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 1234, High: 1234},
		DestinationPort: flow.Interval{Low: port, High: port}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255},
	})}
}

// Query reaches the last explicit permit. Parsing is excluded from timing.
func BenchmarkQuery(b *testing.B) {
	for _, vendor := range parsers {
		for _, n := range []int{10, 100, 1000} {
			b.Run(fmt.Sprintf("%s/rules=%d", vendor.name, n), func(b *testing.B) {
				ctx := context.Background()
				fw, err := vendor.parse(ctx, config.Source{Text: nativeConfig(vendor.name, n), Complete: true}, fm.Metadata{Device: "synthetic-benchmark", Software: "7.4.0"})
				if err != nil {
					b.Fatal(err)
				}
				q := request(b, n-1, 443)
				if vendor.name == "asa" {
					q.RuleSet = "inbound"
				}
				if vendor.name == "fortinet" {
					q.Scope = fw.Metadata().Context
				}
				b.ReportAllocs()
				for b.Loop() {
					got, err := (policy.Engine{}).Query(ctx, fw, q)
					if err != nil || !got.Complete || got.Allowed.Empty() {
						b.Fatalf("last permit: %+v, %v", got, err)
					}
				}
			})
		}
	}
}

func natFirewall(tb testing.TB, n int) *fm.Firewall {
	tb.Helper()
	var raw strings.Builder
	raw.WriteString(nativeConfig("huawei", n))
	raw.WriteString("nat address-group outbound 1\n section 0 203.0.113.100 203.0.113.110\n mode pat\n#\nnat-policy\n")
	for i := range n {
		fmt.Fprintf(&raw, " rule name source-%d\n  source-zone inside\n  destination-zone outside\n  source-address address-set host-%d\n  action source-nat address-group outbound\n", i, i)
	}
	raw.WriteString("#\n")
	fw, err := huawei.Parse(context.Background(), config.Source{Text: raw.String(), Complete: true}, fm.Metadata{Device: "synthetic-benchmark"})
	if err != nil {
		tb.Fatal(err)
	}
	if !fw.Complete() || len(fw.DynamicNATs()) != n {
		tb.Fatal(fw.Diagnostics())
	}
	return fw
}

func BenchmarkNAT(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("huawei/rules=%d", n), func(b *testing.B) {
			fw, q, ctx := natFirewall(b, n), request(b, n-1, 443), context.Background()
			b.ReportAllocs()
			for b.Loop() {
				got, err := (policy.Engine{}).QueryNAT(ctx, fw, q)
				if err != nil || !got.Complete || len(got.Relations) != 1 || !got.Relations[0].PossibleAllocation {
					b.Fatalf("source allocation: %+v, %v", got, err)
				}
			}
		})
	}
}

func BenchmarkPacket(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("huawei/rules=%d", n), func(b *testing.B) {
			fw, q, ctx := natFirewall(b, n), request(b, n-1, 443), context.Background()
			b.ReportAllocs()
			for b.Loop() {
				got, err := (policy.Engine{}).QueryPacket(ctx, fw, policy.PacketRequest{Request: q})
				if err != nil || !got.Complete || len(got.Paths) != 1 || got.Paths[0].Policy.Allowed.Empty() {
					b.Fatalf("routed source allocation: %+v, %v", got, err)
				}
			}
		})
	}
}

func BenchmarkPlan(b *testing.B) {
	// Measure changing plans at 10 and 100 rules to bound whole-graph proof
	// cost. Reuse also covers 1000 rules without candidate expansion.
	for _, kind := range []string{"reuse", "create"} {
		for _, n := range []int{10, 100, 1000} {
			if kind == "create" && n > 100 {
				continue
			}
			b.Run(fmt.Sprintf("%s/rules=%d", kind, n), func(b *testing.B) {
				fw, q, ctx := benchmarkFirewall(b, n), request(b, n-1, 443), context.Background()
				if kind == "create" {
					q = request(b, n+1, 8443)
				}
				// Candidate construction now charges every catalog traversal. Keep the
				// stress workload measurable with an explicit allowance.
				planner := plan.Planner{Renderer: huawei.Renderer{}, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 2_000_000}}}
				requests := []policy.Request{q}
				b.ReportAllocs()
				for b.Loop() {
					got, err := planner.Plan(ctx, fw, requests)
					if err != nil {
						b.Fatal(err)
					}
					if !got.Proof().TargetSatisfied || (kind == "create" && got.Cost().NewRules != 1) {
						b.Fatal("unexpected plan", got.Proof(), got.Cost())
					}
				}
			})
		}
	}
}

package analysis_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors"
)

func readBusinessOracle(t *testing.T, name string, value any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata/perl-business", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, value); err != nil {
		t.Fatal(name, err)
	}
}
func oracleBox(src, dst flow.AddressRange, port flow.Interval) flow.TrafficRegion {
	return flow.TrafficRegion{Source: src, Destination: dst, Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{High: 65535}, DestinationPort: port, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}}
}
func TestBusinessOracleArtifacts(t *testing.T) {
	var manifest map[string]string
	readBusinessOracle(t, "artifacts.json", &manifest)
	if len(manifest) < 100 {
		t.Fatal("incomplete evidence")
	}
	for name, want := range manifest {
		b, err := os.ReadFile(filepath.Join("testdata/perl-business", name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != want {
			t.Fatal("oracle artifact changed", name)
		}
	}
}
func TestActualPerlOptimizerExactTrafficAndProvenance(t *testing.T) {
	var cases []struct {
		Name  string
		Rules []struct {
			Src, Dst []struct{ IP []string }
			Srv      []struct{ Port []string }
		}
	}
	var expected []struct {
		Name  string
		Rules []struct {
			Sources, Destinations [][2]string
			Services              [][2]int
		}
	}
	readBusinessOracle(t, "optimizer-input.json", &cases)
	readBusinessOracle(t, "optimizer.json", &expected)
	for i, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			var requests []policy.Request
			for _, r := range c.Rules {
				var boxes []flow.TrafficRegion
				for _, src := range r.Src {
					for _, s := range src.IP {
						for _, dst := range r.Dst {
							for _, d := range dst.IP {
								for _, service := range r.Srv {
									for _, value := range service.Port {
										sa, err := flow.PrefixRange(netip.MustParsePrefix(s))
										if err != nil {
											t.Fatal(err)
										}
										da, err := flow.PrefixRange(netip.MustParsePrefix(d))
										if err != nil {
											t.Fatal(err)
										}
										port, err := strconv.Atoi(strings.TrimPrefix(value, "tcp/"))
										if err != nil {
											t.Fatal(err)
										}
										boxes = append(boxes, oracleBox(sa, da, flow.Interval{Low: uint16(port), High: uint16(port)}))
									}
								}
							}
						}
					}
				}
				traffic, err := flow.NewTraffic(4096, boxes...)
				if err != nil {
					t.Fatal(err)
				}
				requests = append(requests, policy.Request{Traffic: traffic, FromZone: "inside", ToZone: "outside"})
			}
			if expected[i].Name != c.Name {
				t.Fatal("oracle order")
			}
			var boxes []flow.TrafficRegion
			for _, r := range expected[i].Rules {
				for _, s := range r.Sources {
					for _, d := range r.Destinations {
						for _, port := range r.Services {
							if port[0] < 100000 || port[1] > 165535 {
								t.Fatal("unsupported Perl protocol offset")
							}
							boxes = append(boxes, oracleBox(flow.AddressRange{First: netip.MustParseAddr(s[0]), Last: netip.MustParseAddr(s[1])}, flow.AddressRange{First: netip.MustParseAddr(d[0]), Last: netip.MustParseAddr(d[1])}, flow.Interval{Low: uint16(port[0] - 100000), High: uint16(port[1] - 100000)}))
						}
					}
				}
			}
			want, err := flow.NewTraffic(4096, boxes...)
			if err != nil {
				t.Fatal(err)
			}
			got, err := (analysis.Optimizer{}).Optimize(t.Context(), requests)
			if err != nil || len(got) != 1 || len(got[0].Inputs) != len(requests) {
				t.Fatal(got, err)
			}
			same, err := got[0].Request.Traffic.Equal(want, 4096)
			if err != nil || !same {
				t.Fatal("Perl exact traffic differs", err)
			}
			for i, origin := range got[0].Inputs {
				if origin != i {
					t.Fatal("input provenance lost")
				}
			}
		})
	}
}

func TestActualPerlSearchAndExplicitNativeDifferences(t *testing.T) {
	for _, vendor := range []string{"hillstone", "fortinet", "huawei", "srx", "netscreen", "asa"} {
		t.Run(vendor, func(t *testing.T) {
			var golden struct{ Cases []struct{ Name, Type string } }
			readBusinessOracle(t, vendor+"-search.json", &golden)
			raw, err := os.ReadFile("testdata/perl-business/" + vendor + ".cfg")
			if err != nil {
				t.Fatal(err)
			}
			fw, err := (vendors.Parser{}).Parse(t.Context(), config.Source{Text: string(raw), Complete: true}, fm.Metadata{Device: "oracle", Vendor: vendor, Software: map[string]string{"hillstone": "5.5R8P1", "fortinet": "7.4.0", "asa": "9.16"}[vendor]})
			if err != nil || !fw.Complete() {
				t.Fatal(err)
			}
			var rule fm.RuleRecord
			for _, r := range fw.Rules() {
				if !r.Builtin() {
					rule = r.Record()
					break
				}
			}
			q := policy.Request{Scope: rule.Scope, RuleSet: rule.RuleSet}
			if len(rule.Match.FromZones) > 0 {
				q.FromZone = rule.Match.FromZones[0]
			} else {
				q.FromZone = fw.Zones()[0].ID()
			}
			q.ToZone = q.FromZone
			if len(rule.Match.ToZones) > 0 {
				q.ToZone = rule.Match.ToZones[0]
			}
			renderer, _ := vendors.Renderer(vendor)
			cases := []struct {
				src, dst string
				ports    []uint16
			}{{"192.0.2.10", "192.0.2.10", []uint16{80, 443}}, {"192.0.2.11", "192.0.2.10", []uint16{80, 443}}, {"192.0.2.11", "192.0.2.12", []uint16{80, 443}}, {"192.0.2.10", "192.0.2.10", []uint16{8080}}}
			for i, c := range cases {
				var boxes []flow.TrafficRegion
				s, d := netip.MustParseAddr(c.src), netip.MustParseAddr(c.dst)
				for _, port := range c.ports {
					boxes = append(boxes, oracleBox(flow.AddressRange{First: s, Last: s}, flow.AddressRange{First: d, Last: d}, flow.Interval{Low: port, High: port}))
				}
				q.Traffic, err = flow.NewTraffic(4096, boxes...)
				if err != nil {
					t.Fatal(err)
				}
				p, err := (plan.Planner{Renderer: renderer}).Plan(t.Context(), fw, []policy.Request{q})
				if vendor == "asa" && i > 0 {
					if err == nil || p != nil {
						t.Fatal("unbound ASA representation became executable")
					}
					continue
				}
				if err != nil || !p.Proof().OutsidePreserved || !p.Proof().NATUnchanged {
					t.Fatal(err)
				}
				kind := "ignore"
				if changes := p.Changes(); len(changes) > 0 {
					kind = "modify"
					if changes[0].Kind == plan.CreateRule {
						kind = "new"
					}
				}
				want := golden.Cases[i].Type
				if vendor == "netscreen" {
					want = "ignore"
				} // Established native intrazone permit.
				if vendor == "fortinet" && i == 0 {
					want = "modify"
				} // Native default excludes source port 0.
				if vendor == "fortinet" && i == 1 {
					want = "new"
				} // Full source-port intent cannot safely append here.
				if kind != want {
					t.Fatal(golden.Cases[i].Name, kind, want)
				}
			}
		})
	}
}

func TestActualPerlScheduleBoundaryConversion(t *testing.T) {
	var rows []struct {
		Vendor string
		Checks []struct {
			Active int
			At     int64 `json:"at_epoch"`
		}
	}
	readBusinessOracle(t, "schedule-boundaries.json", &rows)
	if len(rows) != 4 {
		t.Fatal(len(rows))
	}
	for _, row := range rows {
		c := fm.ScheduleClock{Timezone: "UTC", Reference: "actual Perl process-time comparison only", EndBoundary: "inclusive", TickSeconds: 1}
		w, err := c.ParseWindow("2006-01-02 15:04:05", "2026-11-01 09:00:00", "2026-11-01 10:00:00")
		if err != nil {
			t.Fatal(err)
		}
		for _, check := range row.Checks {
			at := time.Unix(check.At, 0)
			active := !at.Before(w.Start) && at.Before(w.End)
			if active != (check.Active == 1) {
				t.Fatal(row.Vendor, check)
			}
		}
	}
}

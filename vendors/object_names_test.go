package vendors_test

import (
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors"
	"github.com/gatework/firemon/vendors/paloalto"
)

func TestCommandsRequireObjectAndRuleNames(t *testing.T) {
	for _, kind := range []string{"address", "service", "zone", "rule"} {
		t.Run(kind, func(t *testing.T) {
			data := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "paloalto"}}
			rule := fm.RuleRecord{
				Object: fm.Object{ID: "graph-rule", Name: "allow-web"}, RuleSet: "security", Action: fm.Permit,
				Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant,
				Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true},
			}
			want := "allow-web"
			switch kind {
			case "address":
				want = "web-client"
				ip := netip.MustParseAddr("192.0.2.1")
				data.Addresses = []fm.AddressRecord{{Object: fm.Object{ID: "graph-address", Name: want}, Ranges: []flow.AddressRange{{First: ip, Last: ip}}}}
				rule.Match.AnySource = false
				rule.Match.Sources = []fm.AddressRef{{Kind: fm.AddressObject, ID: "graph-address"}}
			case "service":
				want = "web-service"
				data.Services = []fm.ServiceRecord{{Object: fm.Object{ID: "graph-service", Name: want}, Terms: []fm.ServiceTerm{{Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 0, High: 65535}, DestinationPort: flow.Interval{Low: 443, High: 443}}}}}
				rule.Match.AnyService = false
				rule.Match.Services = []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "graph-service"}}
			case "zone":
				want = "trusted"
				data.Zones = []fm.ZoneRecord{{Object: fm.Object{ID: "graph-zone", Name: want}}}
				rule.Match.AnyFromZone = false
				rule.Match.FromZones = []fm.ID{"graph-zone"}
			}
			changes := []plan.Change{{Kind: plan.CreateRule, Rule: rule.ID, Sources: rule.Match.Sources, Services: rule.Match.Services}}
			for _, named := range []bool{true, false} {
				if !named {
					switch kind {
					case "address":
						data.Addresses[0].Name = ""
					case "service":
						data.Services[0].Name = ""
					case "zone":
						data.Zones[0].Name = ""
					case "rule":
						rule.Name = ""
					}
				}
				data.Rules = nil
				before, err := fm.Seal(data)
				if err != nil {
					t.Fatal(err)
				}
				data.Rules = []fm.RuleRecord{rule}
				after, err := fm.Seal(data)
				if err != nil || !before.Complete() || !after.Complete() {
					t.Fatal("invalid synthetic graph", err)
				}
				commands, err := (paloalto.Renderer{}).Render(t.Context(), before, after, changes)
				if named {
					if err != nil || !strings.Contains(strings.Join(commands, "\n"), want) {
						t.Fatalf("configuration name missing: %v, %v", commands, err)
					}
				} else if !errors.Is(err, plan.ErrRender) || commands != nil {
					t.Fatalf("graph ID substituted for missing name: %v, %v", commands, err)
				}
			}
		})
	}
}

func TestMemberReferencesRequireNames(t *testing.T) {
	for _, tc := range []struct{ vendor, fixture, kind string }{
		{"fortinet", "fortinet/testdata/basic.conf", "address"},
		{"fortinet", "fortinet/testdata/basic.conf", "service"},
		{"netscreen", "netscreen/testdata/basic.set", "service"},
	} {
		t.Run(tc.vendor+"/"+tc.kind, func(t *testing.T) {
			raw, err := os.ReadFile(tc.fixture)
			if err != nil {
				t.Fatal(err)
			}
			fw, err := (vendors.Parser{}).Parse(t.Context(), config.Source{Text: string(raw), Complete: true}, fm.Metadata{Device: "fw", Vendor: tc.vendor})
			if err != nil {
				t.Fatal(err)
			}
			renderer, err := vendors.Renderer(tc.vendor)
			if err != nil {
				t.Fatal(err)
			}
			for _, named := range []bool{true, false} {
				data := fw.Export()
				if !named {
					if tc.kind == "address" {
						for i := range data.Addresses {
							data.Addresses[i].Name = ""
						}
						for i := range data.AddressGroups {
							data.AddressGroups[i].Name = ""
						}
					} else {
						for i := range data.Services {
							data.Services[i].Name = ""
						}
						for i := range data.ServiceGroups {
							data.ServiceGroups[i].Name = ""
						}
					}
				}
				before, err := fm.Seal(data)
				if err != nil {
					t.Fatal(err)
				}
				rule := before.Rule("10").Record()
				rule.ID, rule.Name, rule.Position = "1", "created", -1
				rule.Log, rule.LogStart, rule.LogEnd = fm.Irrelevant, fm.Irrelevant, fm.Irrelevant
				data.Rules = append(data.Rules, rule)
				after, err := fm.Seal(data)
				if err != nil {
					t.Fatal(err)
				}
				changes := []plan.Change{{Kind: plan.CreateRule, Rule: rule.ID, Sources: rule.Match.Sources, Destinations: rule.Match.Destinations, Services: rule.Match.Services}}
				commands, err := renderer.Render(t.Context(), before, after, changes)
				if named {
					if err != nil || len(commands) == 0 {
						t.Fatal("named references rejected", commands, err)
					}
				} else if !errors.Is(err, plan.ErrRender) || commands != nil {
					t.Fatal("graph ID used as an object name", commands, err)
				}
			}
		})
	}
}

func TestPANInsertionRequiresAnchorName(t *testing.T) {
	for _, name := range []string{"deny-rest", ""} {
		t.Run(name, func(t *testing.T) {
			prior := fm.RuleRecord{
				Object: fm.Object{ID: "prior-id", Name: name}, RuleSet: "security", Position: 10, Action: fm.Deny,
				Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant,
				Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true},
			}
			data := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "paloalto"}, Rules: []fm.RuleRecord{prior}}
			before, err := fm.Seal(data)
			if err != nil {
				t.Fatal(err)
			}
			next := prior
			next.ID, next.Name, next.Position, next.Action = "next-id", "allow-web", 0, fm.Permit
			data.Rules = append(data.Rules, next)
			after, err := fm.Seal(data)
			if err != nil {
				t.Fatal(err)
			}
			commands, err := (paloalto.Renderer{}).Render(t.Context(), before, after, []plan.Change{{Kind: plan.CreateRule, Rule: next.ID}})
			if name != "" {
				if err != nil || !strings.Contains(strings.Join(commands, "\n"), `move rulebase security rules "allow-web" before "deny-rest"`) {
					t.Fatal("insertion order lost", commands, err)
				}
			} else if !errors.Is(err, plan.ErrRender) || commands != nil {
				t.Fatal("missing anchor name accepted", commands, err)
			}
		})
	}
}

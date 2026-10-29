package vendors_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"net/netip"
	"slices"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors"
	"github.com/gatework/firemon/vendors/asa"
	"github.com/gatework/firemon/vendors/fortinet"
	"github.com/gatework/firemon/vendors/hillstone"
	"github.com/gatework/firemon/vendors/huawei"
	"github.com/gatework/firemon/vendors/netscreen"
	"github.com/gatework/firemon/vendors/paloalto"
	"github.com/gatework/firemon/vendors/srx"
)

func TestRendererEntryContract(t *testing.T) {
	natives := map[string]plan.Renderer{"asa": asa.Renderer{}, "fortinet": fortinet.Renderer{}, "hillstone": hillstone.Renderer{}, "huawei": huawei.Renderer{}, "netscreen": netscreen.Renderer{}, "paloalto": paloalto.Renderer{}, "srx": srx.Renderer{}}
	for vendor, direct := range natives {
		registered, err := vendors.Renderer(vendor)
		if err != nil {
			t.Fatal(err)
		}
		for name, renderer := range map[string]plan.Renderer{"direct": direct, "registry": registered} {
			t.Run(vendor+"/"+name, func(t *testing.T) {
				data := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: vendor, Context: "root"}}
				before, err := fm.Seal(data)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if commands, err := renderer.Render(ctx, nil, nil, nil); !errors.Is(err, context.Canceled) || commands != nil {
					t.Fatalf("cancellation: %v %v", commands, err)
				}
				if commands, err := renderer.Render(context.Background(), before, before, nil); err != nil || len(commands) != 0 {
					t.Fatalf("no-op: %v %v", commands, err)
				}
				data.Diagnostics = []fm.Diagnostic{{Code: "unknown", Message: "unmodeled policy"}}
				incomplete, _ := fm.Seal(data)
				if commands, err := renderer.Render(context.Background(), incomplete, incomplete, nil); !errors.Is(err, plan.ErrUnsafe) || commands != nil {
					t.Fatalf("incomplete: %v %v", commands, err)
				}
				data = before.Export()
				data.Metadata.Device = "other"
				after, _ := fm.Seal(data)
				if commands, err := renderer.Render(context.Background(), before, after, nil); !errors.Is(err, plan.ErrInvalid) || commands != nil {
					t.Fatalf("identity: %v %v", commands, err)
				}
				if commands, err := renderer.Render(context.Background(), before, before, []plan.Change{{Kind: plan.RemoveRule, Rule: "missing"}}); !errors.Is(err, plan.ErrInvalid) || commands != nil {
					t.Fatalf("undeclared rule: %v %v", commands, err)
				}
			})
		}
	}
}

func TestCreationRetainsNativeConditions(t *testing.T) {
	for vendor, renderer := range map[string]plan.Renderer{"hillstone": hillstone.Renderer{}, "paloalto": paloalto.Renderer{}} {
		before, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: vendor}})
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name string
			edit func(*fm.RuleRecord)
		}{
			{"disabled", func(r *fm.RuleRecord) { r.Disabled = true }},
			{"description", func(r *fm.RuleRecord) { r.Description = "must persist" }},
			{"application", func(r *fm.RuleRecord) { r.Match.Applications = []string{"web"} }},
			{"inconsistent logging", func(r *fm.RuleRecord) { r.Log = fm.Known }},
		} {
			t.Run(vendor+"/"+tc.name, func(t *testing.T) {
				r := fm.RuleRecord{Object: fm.Object{ID: "new"}, RuleSet: "security", Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}}
				tc.edit(&r)
				d := before.Export()
				d.Rules = []fm.RuleRecord{r}
				after, err := fm.Seal(d)
				if err != nil {
					t.Fatal(err)
				}
				commands, err := renderer.Render(context.Background(), before, after, []plan.Change{{Kind: plan.CreateRule, Rule: r.ID}})
				want := plan.ErrRender
				if !after.Complete() {
					want = plan.ErrUnsafe
				}
				if !errors.Is(err, want) || commands != nil {
					t.Fatalf("unrepresented condition accepted: %v %v", commands, err)
				}
			})
		}
	}
}

func TestPANCreationRejectsNativeNameCollisions(t *testing.T) {
	rule := fm.RuleRecord{Object: fm.Object{ID: "existing", Name: "existing"}, RuleSet: "security", Position: 10, Action: fm.Deny, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}}
	before, _ := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "paloalto"}, Rules: []fm.RuleRecord{rule}})
	d := before.Export()
	rule.ID = "new"
	rule.Position = 0
	rule.Action = fm.Permit
	d.Rules = append(d.Rules, rule)
	after, _ := fm.Seal(d)
	commands, err := (paloalto.Renderer{}).Render(context.Background(), before, after, []plan.Change{{Kind: plan.CreateRule, Rule: "new"}})
	if !errors.Is(err, plan.ErrRender) || commands != nil {
		t.Fatalf("creation targets existing native rule: %v %v", commands, err)
	}
}

func TestPANAnyCreationRoundTripsThroughParser(t *testing.T) {
	before, _ := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "paloalto"}})
	rule := fm.RuleRecord{Object: fm.Object{ID: "new", Name: "new"}, RuleSet: "security", Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}}
	d := before.Export()
	d.Rules = []fm.RuleRecord{rule}
	after, _ := fm.Seal(d)
	commands, err := (paloalto.Renderer{}).Render(context.Background(), before, after, []plan.Change{{Kind: plan.CreateRule, Rule: "new"}})
	if err != nil {
		t.Fatal(err)
	}
	var native []string
	for _, c := range commands {
		if strings.HasPrefix(c, "set ") {
			native = append(native, c)
		}
	}
	parsed, err := paloalto.Parse(context.Background(), config.Source{Text: strings.Join(native, "\n") + "\n", Complete: true}, fm.Metadata{Device: "fw"})
	if err != nil || !parsed.Complete() {
		t.Fatalf("any command readback: %v %v", err, parsed.Diagnostics())
	}
	r := parsed.Rule("new").Record()
	if !r.Match.AnySource || !r.Match.AnyDestination || !r.Match.AnyService {
		t.Fatal("any semantics lost")
	}
}

func TestRendererRejectsEmptyMatchDimensions(t *testing.T) {
	for vendor, renderer := range map[string]plan.Renderer{"hillstone": hillstone.Renderer{}, "paloalto": paloalto.Renderer{}, "srx": srx.Renderer{}} {
		t.Run(vendor, func(t *testing.T) {
			before, _ := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: vendor}})
			r := fm.RuleRecord{Object: fm.Object{ID: "new"}, RuleSet: "security", Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, Match: fm.Match{AnyFromZone: true, AnyToZone: true}}
			d := before.Export()
			d.Rules = []fm.RuleRecord{r}
			after, _ := fm.Seal(d)
			commands, err := renderer.Render(context.Background(), before, after, []plan.Change{{Kind: plan.CreateRule, Rule: "new"}})
			if !errors.Is(err, plan.ErrRender) && !errors.Is(err, plan.ErrUnsafe) || commands != nil {
				t.Fatalf("empty became native default: %v %v", commands, err)
			}
		})
	}
}

func TestInertInlineAdditionDoesNotRenderDeclaration(t *testing.T) {
	for vendor, renderer := range map[string]plan.Renderer{"hillstone": hillstone.Renderer{}, "paloalto": paloalto.Renderer{}} {
		t.Run(vendor, func(t *testing.T) {
			before, _ := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: vendor}})
			d := before.Export()
			d.Addresses = []fm.AddressRecord{{Object: fm.Object{ID: "orphan", Inline: true}, Ranges: []flow.Range{{First: netip.MustParseAddr("192.0.2.1"), Last: netip.MustParseAddr("192.0.2.1")}}}}
			after, _ := fm.Seal(d)
			if commands, err := renderer.Render(context.Background(), before, after, nil); err != nil || len(commands) != 0 {
				t.Fatalf("semantic no-op: %v %v", commands, err)
			}
			d.Rules = []fm.RuleRecord{{Object: fm.Object{ID: "new", Name: "new"}, RuleSet: "security", Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}}}
			after, _ = fm.Seal(d)
			commands, err := renderer.Render(context.Background(), before, after, []plan.Change{{Kind: plan.CreateRule, Rule: "new"}})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(strings.Join(commands, "\n"), "orphan") {
				t.Fatal("orphan inline became declaration", commands)
			}
		})
	}
}

func TestPANObjectCreationRejectsNativeNamespaceCollision(t *testing.T) {
	for _, group := range []bool{false, true} {
		t.Run(fmt.Sprint("group=", group), func(t *testing.T) {
			existing := fm.AddressRecord{Object: fm.Object{ID: "existing", Name: "taken"}, Ranges: []flow.Range{{First: netip.MustParseAddr("192.0.2.1"), Last: netip.MustParseAddr("192.0.2.1")}}}
			d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "paloalto"}}
			if group {
				d.AddressGroups = []fm.AddressGroupRecord{{Object: fm.Object{ID: "group", Name: "taken"}}}
			} else {
				d.Addresses = []fm.AddressRecord{existing}
			}
			before, err := fm.Seal(d)
			if err != nil {
				t.Fatal(err)
			}
			added := existing
			added.ID = "taken"
			d.Addresses = append(d.Addresses, added)
			ref := fm.AddressRef{Kind: fm.AddressObject, ID: added.ID}
			d.Rules = []fm.RuleRecord{{Object: fm.Object{ID: "new", Name: "new"}, RuleSet: "security", Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, Match: fm.Match{Sources: []fm.AddressRef{ref}, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}}}
			after, err := fm.Seal(d)
			if err != nil {
				t.Fatal(err)
			}
			commands, err := (paloalto.Renderer{}).Render(context.Background(), before, after, []plan.Change{{Kind: plan.CreateRule, Rule: "new", Sources: []fm.AddressRef{ref}}})
			if !errors.Is(err, plan.ErrRender) || commands != nil {
				t.Fatalf("native address alias collision: %v %v", commands, err)
			}
		})
	}
}

func TestNativeInsertionAnchorsUsePositionAndIdentity(t *testing.T) {
	for vendor, renderer := range map[string]plan.Renderer{"srx": srx.Renderer{}, "huawei": huawei.Renderer{}} {
		t.Run(vendor, func(t *testing.T) {
			r := fm.RuleRecord{Object: fm.Object{ID: "b", Name: "b"}, RuleSet: "security", Action: fm.Deny, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, FromZones: []fm.ID{"z1"}, ToZones: []fm.ID{"z2"}}}
			d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: vendor}, Zones: []fm.ZoneRecord{{Object: fm.Object{ID: "z1", Name: "z1"}}, {Object: fm.Object{ID: "z2", Name: "z2"}}}, Rules: []fm.RuleRecord{r}}
			r.ID = "a"
			r.Name = "a"
			d.Rules = append(d.Rules, r)
			before, _ := fm.Seal(d)
			r.ID = "c"
			r.Name = "c"
			r.Position = -1
			r.Action = fm.Permit
			d.Rules = append(d.Rules, r)
			after, _ := fm.Seal(d)
			commands, err := renderer.Render(context.Background(), before, after, []plan.Change{{Kind: plan.CreateRule, Rule: "c"}})
			if err != nil {
				t.Fatal(err)
			}
			want := "insert security policies from-zone z1 to-zone z2 policy c before policy a"
			if vendor == "huawei" {
				want = "rule move \"c\" before \"a\""
			}
			if !slices.Contains(commands, want) {
				t.Fatalf("incorrect tied anchor: %v", commands)
			}
		})
	}
}

func TestNetscreenTopCreationReversesIdentityTies(t *testing.T) {
	raw := "set interface ethernet0/1 zone Trust\nset interface ethernet0/1 ip 192.0.2.1/24\nset interface ethernet0/2 zone Untrust\nset interface ethernet0/2 ip 198.51.100.1/24\nset policy id 10 from Trust to Untrust Any Any ANY deny\nexit\n"
	before, err := netscreen.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "fw"})
	if err != nil {
		t.Fatal(err)
	}
	d := before.Export()
	var changes []plan.Change
	for _, id := range []fm.ID{"a", "b"} {
		r := before.Rule("10").Record()
		r.ID = id
		r.Name = string(id)
		r.Position = -1
		if id == "a" {
			r.Action = fm.Permit
		}
		d.Rules = append(d.Rules, r)
		changes = append(changes, plan.Change{Kind: plan.CreateRule, Rule: id, Sources: r.Match.Sources, Destinations: r.Match.Destinations, Services: r.Match.Services})
	}
	after, _ := fm.Seal(d)
	commands, err := (netscreen.Renderer{}).Render(context.Background(), before, after, changes)
	if err != nil {
		t.Fatal(err)
	}
	var policies []string
	for _, c := range commands {
		if strings.Contains(c, " top ") {
			policies = append(policies, c)
		}
	}
	if len(policies) != 2 || !strings.HasSuffix(policies[0], " deny") || !strings.HasSuffix(policies[1], " permit") {
		t.Fatalf("top reversed final semantic order: %v", commands)
	}
}

func TestNewDeclarationRetainsNativeIdentity(t *testing.T) {
	for vendor, renderer := range map[string]plan.Renderer{"hillstone": hillstone.Renderer{}, "paloalto": paloalto.Renderer{}} {
		t.Run(vendor, func(t *testing.T) {
			before, _ := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: vendor}})
			d := before.Export()
			d.Addresses = []fm.AddressRecord{{Object: fm.Object{ID: "abstract-id", Name: "native-name"}, Ranges: []flow.Range{{First: netip.MustParseAddr("192.0.2.1"), Last: netip.MustParseAddr("192.0.2.1")}}}}
			ref := fm.AddressRef{Kind: fm.AddressObject, ID: "abstract-id"}
			d.Rules = []fm.RuleRecord{{Object: fm.Object{ID: "new", Name: "new"}, RuleSet: "security", Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, Match: fm.Match{Sources: []fm.AddressRef{ref}, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}}}
			after, _ := fm.Seal(d)
			commands, err := renderer.Render(context.Background(), before, after, []plan.Change{{Kind: plan.CreateRule, Rule: "new", Sources: []fm.AddressRef{ref}}})
			if !errors.Is(err, plan.ErrRender) || commands != nil {
				t.Fatalf("unrestorable native object identity: %v %v", commands, err)
			}
		})
	}
}

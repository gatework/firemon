package vendors_test

import (
	"context"
	"errors"
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

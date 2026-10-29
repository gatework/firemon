package plan_test

import (
	"context"
	"errors"
	"github.com/gatework/firemon/flow"
	"reflect"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

func TestPreserveRejectsUndeclaredConfigurationChanges(t *testing.T) {
	before := baseline(t)
	d := before.Export()
	d.Rules[0].Name = "renamed"
	after, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (plan.Planner{}).Preserve(context.Background(), before, after, nil, request(t, "192.0.2.1/32").At); !errors.Is(err, plan.ErrInvalid) {
		t.Fatalf("undeclared rename: %v", err)
	}
}

type failedRenderer struct{ err error }

func (r failedRenderer) Render(context.Context, *fm.Firewall, *fm.Firewall, []plan.Change) ([]string, error) {
	return nil, r.err
}
func TestPlannerPropagatesRendererFailure(t *testing.T) {
	failure := errors.New("renderer dependency failed")
	_, err := (plan.Planner{Renderer: failedRenderer{failure}}).Plan(context.Background(), baseline(t), []policy.Request{request(t, "192.0.2.2/32")})
	if !errors.Is(err, failure) {
		t.Fatalf("render failure hidden: %v", err)
	}
}

func TestValidateChangesAccountsForEntireDelta(t *testing.T) {
	before := baseline(t)
	for _, tc := range []struct {
		name string
		edit func(*fm.Data) []plan.Change
		want error
	}{
		{"append", func(d *fm.Data) []plan.Change {
			a := d.Addresses[0]
			a.ID = "extra"
			d.Addresses = append(d.Addresses, a)
			ref := fm.AddressRef{Kind: fm.AddressObject, ID: a.ID}
			d.Rules[0].Match.Sources = append(d.Rules[0].Match.Sources, ref)
			return []plan.Change{{Kind: plan.AppendMembers, Rule: "10", Sources: []fm.AddressRef{ref}}}
		}, nil},
		{"omitted append", func(d *fm.Data) []plan.Change {
			d.Rules[0].Match.Sources = append(d.Rules[0].Match.Sources, d.Rules[0].Match.Destinations[0])
			return nil
		}, plan.ErrInvalid},
		{"action hidden in append", func(d *fm.Data) []plan.Change {
			d.Rules[0].Action = fm.Deny
			ref := d.Rules[0].Match.Destinations[0]
			d.Rules[0].Match.Sources = append(d.Rules[0].Match.Sources, ref)
			return []plan.Change{{Kind: plan.AppendMembers, Rule: "10", Sources: []fm.AddressRef{ref}}}
		}, plan.ErrInvalid},
		{"duplicate addition", func(d *fm.Data) []plan.Change {
			ref := d.Rules[0].Match.Sources[0]
			return []plan.Change{{Kind: plan.AppendMembers, Rule: "10", Sources: []fm.AddressRef{ref}}}
		}, plan.ErrInvalid},
		{"empty append", func(d *fm.Data) []plan.Change { return []plan.Change{{Kind: plan.AppendMembers, Rule: "10"}} }, plan.ErrInvalid},
		{"undeclared service", func(d *fm.Data) []plan.Change {
			s := d.Services[0]
			s.ID = "extra"
			d.Services = append(d.Services, s)
			return nil
		}, plan.ErrInvalid},
		{"changed shared object", func(d *fm.Data) []plan.Change {
			d.Addresses[0].Ranges = []flow.Range{addressRange("10.0.0.1/32")}
			return nil
		}, plan.ErrInvalid},
		{"remove", func(d *fm.Data) []plan.Change {
			d.Rules = nil
			return []plan.Change{{Kind: plan.RemoveRule, Rule: "10"}}
		}, nil},
		{"undeclared remove", func(d *fm.Data) []plan.Change { d.Rules = nil; return nil }, plan.ErrInvalid},
		{"contradictory changes", func(d *fm.Data) []plan.Change {
			d.Rules = nil
			return []plan.Change{{Kind: plan.RemoveRule, Rule: "10"}, {Kind: plan.CreateRule, Rule: "10"}}
		}, plan.ErrInvalid},
		{"create", func(d *fm.Data) []plan.Change {
			r := d.Rules[0]
			r.ID = "new"
			r.Position = -1
			d.Rules = append(d.Rules, r)
			return []plan.Change{{Kind: plan.CreateRule, Rule: r.ID, Sources: r.Match.Sources, Destinations: r.Match.Destinations, Services: r.Match.Services}}
		}, nil},
		{"incomplete creation members", func(d *fm.Data) []plan.Change {
			r := d.Rules[0]
			r.ID = "new"
			d.Rules = append(d.Rules, r)
			return []plan.Change{{Kind: plan.CreateRule, Rule: r.ID}}
		}, plan.ErrInvalid},
		{"source layout", func(d *fm.Data) []plan.Change {
			d.Raw = "new evidence"
			d.Metadata.SourceDigest = ""
			d.Rules[0].Position = 100
			return nil
		}, nil},
		{"context", func(d *fm.Data) []plan.Change { d.Metadata.Context = "other"; return nil }, plan.ErrInvalid},
		{"software", func(d *fm.Data) []plan.Change { d.Metadata.Software = "other"; return nil }, plan.ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := before.Export()
			changes := tc.edit(&data)
			after, err := fm.Seal(data)
			if err != nil {
				t.Fatal(err)
			}
			if !after.Complete() {
				t.Fatal(after.Diagnostics())
			}
			digest := after.SemanticDigest()
			saved := after.Export()
			err = plan.ValidateChanges(context.Background(), before, after, changes)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v got %v", tc.want, err)
			}
			if digest != after.SemanticDigest() || !reflect.DeepEqual(saved, after.Export()) {
				t.Fatal("input mutated")
			}
		})
	}
}

func TestValidateChangesPreservesSurvivingRuleOrder(t *testing.T) {
	d := baseline(t).Export()
	r := d.Rules[0]
	r.ID = "20"
	r.Position = 1
	d.Rules = append(d.Rules, r)
	before, _ := fm.Seal(d)
	d.Rules[0].Position = 2
	after, _ := fm.Seal(d)
	if err := plan.ValidateChanges(context.Background(), before, after, nil); !errors.Is(err, plan.ErrInvalid) {
		t.Fatalf("reordered: %v", err)
	}
}

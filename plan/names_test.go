package plan_test

import (
	"context"
	"strings"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/hillstone"
)

func namedPlan(t *testing.T, data fm.Data, transfer bool) *plan.Plan {
	t.Helper()
	fw, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	digest := fw.SemanticDigest()
	planner := plan.Planner{Renderer: hillstone.Renderer{}}
	q := request(t, "192.0.2.2/32")
	var result *plan.Plan
	if transfer {
		result, err = planner.Transfer(context.Background(), fw, []plan.RuleIntent{{
			Request: q, Action: fm.Permit,
			Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant,
		}}, time.Time{})
	} else {
		result, err = planner.Plan(context.Background(), fw, []policy.Request{q})
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Commands()) == 0 || !result.Proof().TargetSatisfied || fw.SemanticDigest() != digest {
		t.Fatal("missing proven commands or mutated baseline")
	}
	return result
}

func TestPlanningAvoidsOccupiedGeneratedIdentities(t *testing.T) {
	for _, transfer := range []bool{false, true} {
		mode := "plan"
		if transfer {
			mode = "transfer"
		}
		t.Run(mode, func(t *testing.T) {
			base := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}}
			first := namedPlan(t, base, transfer)
			service := first.After().Services()[0].Record()
			rule := first.After().Rules()[0].Record()
			address := first.After().Addresses()[0].Record()
			for _, kind := range []string{"service-ids", "service-name", "service-group-name", "scoped-address-name", "scoped-address-group-name", "rule-ids"} {
				t.Run(kind, func(t *testing.T) {
					data := base
					occupied := service.ID
					switch kind {
					case "service-ids":
						other := service
						other.Terms = nil // Must not reuse the requested service.
						other.ID, other.Name = service.ID+"-new", string(service.ID)+"-new"
						data.Services = append(data.Services, other)
						other.ID, other.Name = service.ID, string(service.ID)
						data.Services = append(data.Services, other)
					case "service-name":
						data.Services = []fm.ServiceRecord{{Object: fm.Object{ID: "other-service", Name: string(service.ID)}}}
					case "service-group-name":
						data.ServiceGroups = []fm.ServiceGroupRecord{{Object: fm.Object{ID: "group", Name: string(service.ID)}}}
					case "scoped-address-name", "scoped-address-group-name":
						occupied = address.ID
						object := fm.Object{ID: "local", Name: string(address.ID), Scope: "local-book"}
						if kind == "scoped-address-name" {
							data.Addresses = []fm.AddressRecord{{Object: object}}
						} else {
							data.AddressGroups = []fm.AddressGroupRecord{{Object: object}}
						}
					case "rule-ids":
						occupied = rule.ID
						other := fm.RuleRecord{RuleSet: "security", Disabled: true, Action: fm.Permit, Log: fm.Irrelevant}
						other.ID, other.Name = rule.ID+"-new", string(rule.ID)+"-new"
						data.Rules = append(data.Rules, other)
						other.ID, other.Name, other.Position = rule.ID, string(rule.ID), 1
						data.Rules = append(data.Rules, other)
					}
					result := namedPlan(t, data, transfer)
					want := string(occupied) + "-new"
					if strings.HasSuffix(kind, "ids") {
						want += "-new"
					}
					found := false
					for _, object := range result.After().Export().Services {
						found = found || object.Name == want
					}
					for _, object := range result.After().Export().Addresses {
						found = found || object.Name == want
					}
					for _, object := range result.After().Export().Rules {
						found = found || object.Name == want
					}
					if !found {
						t.Fatalf("free generated name %q missing", want)
					}
				})
			}
		})
	}
}

package plan_test

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/hillstone"
)

func TestPerlOracleCandidateParity(t *testing.T) {
	var fixture struct {
		Config string
		Cases  []struct {
			Name          string
			Src, Dst, Srv []string
			ExpectedType  string  `json:"expected_type"`
			ExpectedRule  *string `json:"expected_rule"`
		}
	}
	raw, err := os.ReadFile("testdata/perl-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	fw, err := hillstone.Parse(context.Background(), config.Source{Text: fixture.Config, Complete: true}, fm.Metadata{Device: "oracle"})
	if err != nil {
		t.Fatal(err)
	}
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			var boxes []flow.TrafficRegion
			for _, src := range tc.Src {
				for _, dst := range tc.Dst {
					for _, srv := range tc.Srv {
						a, _ := flow.PrefixRange(netip.MustParsePrefix(src))
						b, _ := flow.PrefixRange(netip.MustParsePrefix(dst))
						parts := strings.Split(srv, "/")
						port, _ := strconv.Atoi(parts[1])
						boxes = append(boxes, flow.TrafficRegion{Source: a, Destination: b, Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 0, High: 65535}, DestinationPort: flow.Interval{Low: uint16(port), High: uint16(port)}, ICMPType: flow.Interval{Low: 0, High: 255}, ICMPCode: flow.Interval{Low: 0, High: 255}})
					}
				}
			}
			traffic, err := flow.NewTraffic(4096, boxes...)
			if err != nil {
				t.Fatal(err)
			}
			result, err := (plan.Planner{Renderer: hillstone.Renderer{}}).Plan(context.Background(), fw, []policy.Request{{Traffic: traffic, FromZone: "inside", ToZone: "outside"}})
			if err != nil {
				t.Fatal(err)
			}
			got := "ignore"
			if len(result.Changes()) > 0 {
				got = "modify"
				if result.Changes()[0].Kind == plan.CreateRule {
					got = "new"
				}
			}
			if got != tc.ExpectedType {
				t.Fatalf("want %s got %s", tc.ExpectedType, got)
			}
			if got == "modify" && string(result.Changes()[0].Rule) != *tc.ExpectedRule {
				t.Fatalf("expected rule %s got %s", *tc.ExpectedRule, result.Changes()[0].Rule)
			}
		})
	}
}

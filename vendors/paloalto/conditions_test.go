package paloalto_test

import (
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/policy"
)

func TestNeutralConditionsDoNotHideExactService(t *testing.T) {
	raw := "set service web protocol tcp port 443\nset service web protocol tcp override no\n"
	for _, field := range []string{"from any", "to any", "source any", "destination any", "service web", "application any", "source-hip any", "destination-hip any", "category any", "negate-source no", "negate-destination no", "action allow"} {
		raw += "set rulebase security rules web " + field + "\n"
	}
	fw := parse(t, raw)
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	terms, known, err := (policy.Engine{}).ResolveServices(t.Context(), fw, []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "web"}}, false)
	if err != nil || !known || len(terms) != 1 || terms[0].DestinationPort.Low != 443 || terms[0].DestinationPort.High != 443 {
		t.Fatal("service widened or became unknown", terms, err)
	}
	for _, pair := range [][2]string{{"category any", "category restricted"}, {"source-hip any", "source-hip managed"}, {"negate-source no", "negate-source yes"}, {"override no", "override yes timeout 60"}} {
		t.Run(pair[1], func(t *testing.T) {
			if parse(t, strings.Replace(raw, pair[0], pair[1], 1)).Complete() {
				t.Fatal("unsupported effect treated as neutral")
			}
		})
	}
}

func TestServiceProtocolConflictRemainsUnknown(t *testing.T) {
	fw := parse(t, "set service web protocol tcp port 443\nset service web protocol udp override no\n")
	_, known, err := (policy.Engine{}).ResolveServices(t.Context(), fw,
		[]fm.ServiceRef{{Kind: fm.ServiceObject, ID: "web"}}, false)
	if err != nil || known || fw.Complete() {
		t.Fatal("conflicting protocol became an exact service", known, err)
	}
}

func TestApplicationDefaultIsAnUnknownConditionNotAMissingService(t *testing.T) {
	raw := ""
	for _, field := range []string{"from any", "to any", "source any", "destination any", "service application-default", "application ssl", "action allow"} {
		raw += "set rulebase security rules app " + field + "\n"
	}
	fw := parse(t, raw)
	if fw.Complete() || len(fw.Rule("app").Record().Match.Unsupported) == 0 {
		t.Fatal("application defaults became unrestricted")
	}
	for _, d := range fw.Diagnostics() {
		if d.Code == "missing-service" {
			t.Fatal("application default was treated as an object reference")
		}
	}
}

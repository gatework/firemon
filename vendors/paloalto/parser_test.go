package paloalto_test

import (
	"context"
	"os"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/vendors/paloalto"
)

func TestPANRejectAndDropActionsRemainDistinctDeclarations(t *testing.T) {
	seen := make(map[string]bool)
	for _, action := range []string{"deny", "drop", "reset-client", "reset-server", "reset-both"} {
		t.Run(action, func(t *testing.T) {
			var raw strings.Builder
			for _, field := range []string{"from any", "to any", "source any", "destination any", "service any", "application any", "action " + action} {
				raw.WriteString("set rulebase security rules rule " + field + "\n")
			}
			fw, err := paloalto.Parse(context.Background(), config.Source{Text: raw.String(), Complete: true}, fm.Metadata{Device: "pan"})
			if err != nil || !fw.Complete() {
				t.Fatal(err)
			}
			if seen[fw.SemanticDigest()] {
				t.Fatal("native rejection side effect collapsed", action)
			}
			seen[fw.SemanticDigest()] = true
		})
	}
}

func TestSetConfigurationRestoresHostAliasAndNativeNATKinds(t *testing.T) {
	raw, err := os.ReadFile("testdata/basic.cfg")
	if err != nil {
		t.Fatal(err)
	}
	fw, err := paloalto.Parse(context.Background(), config.Source{Text: string(raw), Complete: true}, fm.Metadata{Device: "pan"})
	if err != nil {
		t.Fatal(err)
	}
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	if fw.Interface("ethernet1/2").Record().Addresses[0].String() != "203.0.113.9/24" {
		t.Fatal("address alias lost actual interface host")
	}
	if routeFor(t, fw, "default", "default").Interface() != fw.Interface("ethernet1/2") {
		t.Fatal("route not bound")
	}
	if len(fw.DynamicNATs()) != 2 || fw.DynamicNAT("outbound").Interface() != fw.Interface("ethernet1/2") {
		t.Fatal("dynamic NAT interface reference lost")
	}
	if fw.Rule("allow-web").Schedule() == nil {
		t.Fatal("schedule reference missing")
	}
}
func TestStaticIPNATUsesConcreteStaticCatalogAndUnsupportedApplicationsStayUnknown(t *testing.T) {
	raw := "set address real ip-netmask 192.0.2.0/24\nset address mapped ip-netmask 203.0.113.0/24\nset rulebase nat rules fixed from any\nset rulebase nat rules fixed to any\nset rulebase nat rules fixed source real\nset rulebase nat rules fixed destination any\nset rulebase nat rules fixed service any\nset rulebase nat rules fixed source-translation static-ip translated-address mapped\n"
	fw, err := paloalto.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "pan"})
	if err != nil {
		t.Fatal(err)
	}
	if !fw.Complete() || fw.StaticNAT("fixed") == nil || len(fw.DynamicNATs()) != 0 {
		t.Fatal("static translation collapsed into dynamic/generic rule", fw.Diagnostics())
	}
	raw += "set rulebase security rules app from any\nset rulebase security rules app to any\nset rulebase security rules app source any\nset rulebase security rules app destination any\nset rulebase security rules app application ssl\nset rulebase security rules app service application-default\nset rulebase security rules app action allow\n"
	fw, err = paloalto.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "pan"})
	if err != nil {
		t.Fatal(err)
	}
	if fw.Complete() {
		t.Fatal("app-default became port allow")
	}
}

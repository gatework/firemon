package asa_test

import (
	"context"
	"os"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/vendors/asa"
)

func TestASAParsesInterfacesACLBindingsAndDistinctNATCatalogs(t *testing.T) {
	raw, err := os.ReadFile("testdata/basic.cfg")
	if err != nil {
		t.Fatal(err)
	}
	fw, err := asa.Parse(context.Background(), config.Source{Text: string(raw), Complete: true}, fm.Metadata{Device: "asa"})
	if err != nil {
		t.Fatal(err)
	}
	if fw.Interface("inside0").Zone() != fw.Zone("inside") || len(fw.Rules()) != 2 || len(fw.RuleBindings()) != 1 {
		t.Fatal("ACL/interface graph missing")
	}
	if len(fw.StaticNATs()) != 2 || len(fw.DynamicNATs()) != 1 {
		t.Fatal("NAT object types missing")
	}
	if fw.Complete() {
		t.Fatal("mixed legacy and modern NAT without software evidence became deployable")
	}
}
func TestASAModernObjectAndManualNATKeepNativeSections(t *testing.T) {
	raw := "interface inside0\n nameif inside\n ip address 192.0.2.1 255.255.255.0\n!\ninterface outside0\n nameif outside\n ip address 203.0.113.1 255.255.255.0\n!\nobject network a\n host 192.0.2.10\n nat (inside,outside) static 203.0.113.10\nobject network b\n host 192.0.2.20\nobject network pub\n host 203.0.113.20\nnat (inside,outside) after-auto source static b pub\n"
	fw, err := asa.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "asa", Software: "9.12"})
	if err != nil {
		t.Fatal(err)
	}
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	sequence := fw.NATSequence()
	if len(sequence) != 2 || sequence[0].Order.Stage != 2 || sequence[1].Order.Stage != 3 {
		t.Fatal("ASA NAT sections lost", sequence)
	}
}

func TestAutoNATOrdersByExactObjectCardinalityBeforeAddress(t *testing.T) {
	raw := "interface i\n nameif inside\n!\ninterface o\n nameif outside\n!\nobject network large\n range 192.0.2.0 192.0.2.7\n nat (inside,outside) dynamic 203.0.113.1\nobject network small\n range 192.0.2.8 192.0.2.12\n nat (inside,outside) dynamic 203.0.113.1\n"
	fw, err := asa.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "asa", Software: "9.12"})
	if err != nil {
		t.Fatal(err)
	}
	first := fw.NATSequence()[0]
	if got := fw.DynamicNAT(first.ID).Record().Match.Sources[0].ID; got != "small" {
		t.Fatalf("expected smaller object first, got %s", got)
	}
}

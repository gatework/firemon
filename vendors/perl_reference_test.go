package vendors_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

// The expected projections come from the separately mounted, actual Perl
// implementation. Normal Go tests need neither Perl nor the private source.
func TestSixVendorsMatchPerlReference(t *testing.T) {
	for _, vendor := range []string{"hillstone", "huawei", "fortinet", "srx", "netscreen", "asa"} {
		t.Run(vendor, func(t *testing.T) {
			dir := filepath.Join("testdata", "perl")
			raw, err := os.ReadFile(filepath.Join(dir, vendor+".cfg"))
			if err != nil {
				t.Fatal(err)
			}
			expected, err := os.ReadFile(filepath.Join(dir, vendor+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var want any
			if err := json.Unmarshal(expected, &want); err != nil {
				t.Fatal(err)
			}
			graph, err := (vendors.Parser{}).Parse(context.Background(), config.Source{Text: string(raw), Complete: true}, fm.Metadata{Device: "synthetic-oracle", Vendor: vendor, Software: "7.4.0"})
			if err != nil {
				t.Fatal(err)
			}
			if !graph.Complete() {
				t.Fatal(graph.Diagnostics())
			}
			var data bytes.Buffer
			if err := snapshot.Encode(&data, graph); err != nil {
				t.Fatal(err)
			}
			restored, err := snapshot.Decode(&data, 64<<20)
			if err != nil {
				t.Fatal(err)
			}
			for _, fw := range []*fm.Firewall{graph, restored} {
				wire, err := json.Marshal(perlProjection(t, fw))
				if err != nil {
					t.Fatal(err)
				}
				var got any
				if err := json.Unmarshal(wire, &got); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("Perl projection differs:\ngot %s\nwant %s", wire, expected)
				}
			}
		})
	}
}

func perlProjection(t *testing.T, f *fm.Firewall) map[string]any {
	t.Helper()
	ctx := context.Background()
	addresses := map[string][]string{}
	services := map[string][]string{}
	interfaces := map[string]string{}
	zones := []string{}
	resolveAddresses := func(refs []fm.AddressRef, anyAddress bool) []string {
		set, known, err := (policy.Engine{}).ResolveAddresses(ctx, f, refs, anyAddress)
		if err != nil || !known {
			t.Fatalf("unresolved addresses: %v, %v", known, err)
		}
		out := []string{}
		for _, v := range set.Ranges() {
			out = append(out, v.First.String()+"-"+v.Last.String())
		}
		return out
	}
	resolveServices := func(refs []fm.ServiceRef, anyService bool) []string {
		terms, known, err := (policy.Engine{}).ResolveServices(ctx, f, refs, anyService)
		if err != nil || !known {
			t.Fatalf("unresolved services: %v, %v", known, err)
		}
		out := []string{}
		for _, v := range terms {
			if v.Protocol.Low != 6 || v.Protocol.High != 6 {
				t.Fatalf("unexpected protocol: %v", v)
			}
			out = append(out, fmt.Sprintf("tcp:%d-%d", v.DestinationPort.Low, v.DestinationPort.High))
		}
		return out
	}
	for _, a := range f.Addresses() {
		if a.Name() == "leaf" || a.Name() == "hosts" {
			addresses[a.Name()] = resolveAddresses([]fm.AddressRef{{Kind: fm.AddressObject, ID: a.ID()}}, false)
		}
	}
	for _, a := range f.AddressGroups() {
		if a.Name() == "leaf" || a.Name() == "hosts" {
			addresses[a.Name()] = resolveAddresses([]fm.AddressRef{{Kind: fm.AddressGroupObject, ID: a.ID()}}, false)
		}
	}
	for _, s := range f.Services() {
		if s.Name() == "web" || s.Name() == "apps" {
			services[s.Name()] = resolveServices([]fm.ServiceRef{{Kind: fm.ServiceObject, ID: s.ID()}}, false)
		}
	}
	for _, s := range f.ServiceGroups() {
		if s.Name() == "web" || s.Name() == "apps" {
			services[s.Name()] = resolveServices([]fm.ServiceRef{{Kind: fm.ServiceGroupObject, ID: s.ID()}}, false)
		}
	}
	for _, i := range f.Interfaces() {
		r := i.Record()
		if len(r.Addresses) != 1 || i.Zone() == nil {
			t.Fatalf("unresolved interface: %v", r)
		}
		interfaces[i.Name()] = i.Zone().Name() + ":" + r.Addresses[0].String()
	}
	for _, z := range f.Zones() {
		zones = append(zones, z.Name())
	}
	slices.Sort(zones)
	rules := []map[string]any{}
	for _, rule := range f.Rules() {
		r := rule.Record()
		if r.Builtin {
			continue
		}
		if r.Action != fm.Permit {
			t.Fatalf("unexpected rule action: %v", r.Action)
		}
		rules = append(rules, map[string]any{"action": "permit", "sources": resolveAddresses(r.Match.Sources, r.Match.AnySource), "destinations": resolveAddresses(r.Match.Destinations, r.Match.AnyDestination), "services": resolveServices(r.Match.Services, r.Match.AnyService)})
	}
	return map[string]any{"addresses": addresses, "services": services, "interfaces": interfaces, "zones": zones, "rules": rules}
}

//go:build ignore

package main

import (
	"context"
	"encoding/json"
	"fmt"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors"
	"os"
	"sort"
)

func main() {
	vendor := os.Args[1]
	raw, e := os.ReadFile(os.Args[2])
	if e != nil {
		panic(e)
	}
	f, e := (vendors.Parser{}).Parse(context.Background(), config.Source{Text: string(raw), Complete: true}, fm.Metadata{Device: "synthetic-oracle", Vendor: vendor, Software: "7.4.0"})
	if e != nil {
		panic(e)
	}
	addresses := map[string][]string{}
	services := map[string][]string{}
	interfaces := map[string]string{}
	zones := []string{}
	ar := func(name string, r fm.AddressRef) {
		if name != "leaf" && name != "hosts" {
			return
		}
		s, k, e := (policy.Engine{}).ResolveAddresses(context.Background(), f, []fm.AddressRef{r}, false)
		if e != nil || !k {
			panic(fmt.Sprintf("address %s known=%v err=%v", name, k, e))
		}
		for _, v := range s.Ranges() {
			addresses[name] = append(addresses[name], v.First.String()+"-"+v.Last.String())
		}
	}
	for _, a := range f.Addresses() {
		ar(a.Name(), fm.AddressRef{Kind: fm.AddressObject, ID: a.ID()})
	}
	for _, a := range f.AddressGroups() {
		ar(a.Name(), fm.AddressRef{Kind: fm.AddressGroupObject, ID: a.ID()})
	}
	sr := func(name string, r fm.ServiceRef) {
		if name != "web" && name != "apps" {
			return
		}
		s, k, e := (policy.Engine{}).ResolveServices(context.Background(), f, []fm.ServiceRef{r}, false)
		if e != nil || !k {
			panic(fmt.Sprintf("service %s known=%v err=%v", name, k, e))
		}
		for _, v := range s {
			if v.Protocol.Low != 6 || v.Protocol.High != 6 {
				panic(v)
			}
			services[name] = append(services[name], fmt.Sprintf("tcp:%d-%d", v.DestinationPort.Low, v.DestinationPort.High))
		}
	}
	for _, s := range f.Services() {
		sr(s.Name(), fm.ServiceRef{Kind: fm.ServiceObject, ID: s.ID()})
	}
	for _, s := range f.ServiceGroups() {
		sr(s.Name(), fm.ServiceRef{Kind: fm.ServiceGroupObject, ID: s.ID()})
	}
	for _, i := range f.Interfaces() {
		r := i.Record()
		if len(r.Addresses) != 1 || i.Zone() == nil {
			panic(r)
		}
		interfaces[i.Name()] = i.Zone().Name() + ":" + r.Addresses[0].String()
	}
	for _, z := range f.Zones() {
		zones = append(zones, z.Name())
	}
	sort.Strings(zones)
	rules := []map[string]any{}
	for _, rule := range f.Rules() {
		r := rule.Record()
		if r.Builtin {
			continue
		}
		if r.Action != fm.Permit {
			panic(r.Action)
		}
		addr := func(refs []fm.AddressRef, any bool) []string {
			set, known, err := (policy.Engine{}).ResolveAddresses(context.Background(), f, refs, any)
			if err != nil || !known {
				panic(fmt.Sprintf("rule address %v %v", known, err))
			}
			out := []string{}
			for _, v := range set.Ranges() {
				out = append(out, v.First.String()+"-"+v.Last.String())
			}
			return out
		}
		ts, k, e := (policy.Engine{}).ResolveServices(context.Background(), f, r.Match.Services, r.Match.AnyService)
		if e != nil || !k {
			panic(fmt.Sprintf("rule service %v %v", k, e))
		}
		ports := []string{}
		for _, v := range ts {
			if v.Protocol.Low != 6 || v.Protocol.High != 6 {
				panic(v)
			}
			ports = append(ports, fmt.Sprintf("tcp:%d-%d", v.DestinationPort.Low, v.DestinationPort.High))
		}
		rules = append(rules, map[string]any{"action": "permit", "sources": addr(r.Match.Sources, r.Match.AnySource), "destinations": addr(r.Match.Destinations, r.Match.AnyDestination), "services": ports})
	}
	out := map[string]any{"addresses": addresses, "services": services, "interfaces": interfaces, "zones": zones, "rules": rules}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintln(os.Stderr, "complete:", f.Complete(), "diagnostics:", f.Diagnostics())
}

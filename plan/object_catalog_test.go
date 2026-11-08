package plan_test

import (
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

func TestCatalogReusesOnlyCompleteVisibleCoverage(t *testing.T) {
	for _, kind := range []string{"multi-address", "address-group", "multi-service", "service-group", "wider-address", "service-hole", "foreign-address-group", "foreign-service-group", "shadowed-address", "shadowed-service", "local-service", "address-book-group", "wrong-address-book-group", "shadowed-address-group", "shadowed-service-group"} {
		t.Run(kind, func(t *testing.T) {
			data := baseline(t).Export()
			data.Rules = nil
			data.Zones = []fm.ZoneRecord{{Object: fm.Object{ID: "inside"}}, {Object: fm.Object{ID: "outside"}}}
			q := request(t, "192.0.2.0/30")
			q.FromZone, q.ToZone, q.Scope = "inside", "outside", "selected"
			region := q.Traffic.Regions()[0]
			region.DestinationPort.High = 444
			q.Traffic, _ = flow.NewTraffic(32, region)
			data.Addresses[0].Ranges = []flow.AddressRange{region.Source}
			data.Services[0].Terms[0].DestinationPort = region.DestinationPort
			wantAddress := fm.AddressRef{Kind: fm.AddressObject, ID: "src"}
			wantService := fm.ServiceRef{Kind: fm.ServiceObject, ID: "https"}
			first, second := data.Services[0].Terms[0], data.Services[0].Terms[0]
			first.DestinationPort.High, second.DestinationPort.Low = 443, 444
			switch kind {
			case "multi-address":
				data.Addresses[0].Ranges = []flow.AddressRange{addressRange("192.0.2.0/31"), addressRange("192.0.2.2/31")}
			case "address-group", "foreign-address-group", "address-book-group", "wrong-address-book-group":
				data.Addresses[0].Ranges = []flow.AddressRange{addressRange("192.0.2.0/31")}
				data.Addresses = append(data.Addresses, fm.AddressRecord{Object: fm.Object{ID: "src-second"}, Ranges: []flow.AddressRange{addressRange("192.0.2.2/31")}})
				data.AddressGroups = []fm.AddressGroupRecord{{Object: fm.Object{ID: "source-group"}, Members: []fm.AddressRef{{Kind: fm.AddressObject, ID: "src"}, {Kind: fm.AddressObject, ID: "src-second"}}}}
				wantAddress = fm.AddressRef{Kind: fm.AddressGroupObject, ID: "source-group"}
				if kind == "foreign-address-group" {
					data.AddressGroups[0].Scope = "other"
					wantAddress = fm.AddressRef{}
				}
				if kind == "address-book-group" || kind == "wrong-address-book-group" {
					data.AddressGroups[0].Scope = "book:inside"
					data.Zones[0].AddressScope = "book:inside"
					if kind == "wrong-address-book-group" {
						data.Zones[0].AddressScope = "book:other"
						wantAddress = fm.AddressRef{}
					}
				}
			case "multi-service":
				data.Services[0].Terms = []fm.ServiceTerm{first, second}
			case "service-group", "foreign-service-group":
				data.Services[0].Terms = []fm.ServiceTerm{first}
				data.Services = append(data.Services, fm.ServiceRecord{Object: fm.Object{ID: "second-port"}, Terms: []fm.ServiceTerm{second}})
				data.ServiceGroups = []fm.ServiceGroupRecord{{Object: fm.Object{ID: "service-group"}, Members: []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "https"}, {Kind: fm.ServiceObject, ID: "second-port"}}}}
				wantService = fm.ServiceRef{Kind: fm.ServiceGroupObject, ID: "service-group"}
				if kind == "foreign-service-group" {
					data.ServiceGroups[0].Scope = "other"
					wantService = fm.ServiceRef{}
				}
			case "wider-address":
				data.Addresses[0].Ranges = []flow.AddressRange{addressRange("192.0.2.0/24")}
				wantAddress = fm.AddressRef{}
			case "service-hole":
				region.DestinationPort.High = 445
				q.Traffic, _ = flow.NewTraffic(32, region)
				second.DestinationPort = flow.Interval{Low: 445, High: 445}
				data.Services[0].Terms = []fm.ServiceTerm{first, second}
				wantService = fm.ServiceRef{}
			case "shadowed-address":
				data.Addresses = append(data.Addresses, fm.AddressRecord{Object: fm.Object{ID: "local-source", Name: "src", Scope: "selected"}, Ranges: []flow.AddressRange{addressRange("203.0.113.1/32")}})
				wantAddress = fm.AddressRef{}
			case "shadowed-service":
				data.Services = append(data.Services, fm.ServiceRecord{Object: fm.Object{ID: "local-service", Name: "https", Scope: "selected"}, Terms: []fm.ServiceTerm{first}})
				wantService = fm.ServiceRef{}
			case "shadowed-address-group":
				data.AddressGroups = []fm.AddressGroupRecord{{Object: fm.Object{ID: "shadowing", Name: "src", Scope: "selected"}, Members: []fm.AddressRef{{Kind: fm.AddressObject, ID: "dst"}}}}
				wantAddress = fm.AddressRef{}
			case "shadowed-service-group":
				data.Services = append(data.Services, fm.ServiceRecord{Object: fm.Object{ID: "first-port"}, Terms: []fm.ServiceTerm{first}})
				data.ServiceGroups = []fm.ServiceGroupRecord{{Object: fm.Object{ID: "shadowing", Name: "https", Scope: "selected"}, Members: []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "first-port"}}}}
				wantService = fm.ServiceRef{}
			case "local-service":
				data.Services[0].Scope = "selected"
			}
			fw, err := fm.Seal(data)
			if err != nil {
				t.Fatal(err)
			}
			p, err := (plan.Planner{Renderer: renderer{}}).Plan(t.Context(), fw, []policy.Request{q})
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Changes()) != 1 {
				t.Fatal("one exact partition expected", p.Changes())
			}
			change := p.Changes()[0]
			if wantAddress.ID != "" && change.Sources[0] != wantAddress {
				t.Fatal("exact address declaration not reused", change.Sources)
			}
			if wantAddress.ID == "" && len(p.After().Addresses()) != len(fw.Addresses())+1 {
				t.Fatal("wider or invisible address reused")
			}
			if wantService.ID != "" && change.Services[0] != wantService {
				t.Fatal("exact service declaration not reused", change.Services)
			}
			if wantService.ID == "" && len(p.After().Services()) != len(fw.Services())+1 {
				t.Fatal("inexact or invisible service reused")
			}
			if _, err := p.Verify(t.Context(), p.After()); err != nil {
				t.Fatal("reuse changed proof", err)
			}
		})
	}
}

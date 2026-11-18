package converge_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/converge"
)

func TestDuplicateObjects(t *testing.T) {
	t.Parallel()
	host := func(name, a string) firemon.Address {
		return firemon.Address{Name: name, Entries: []firemon.AddressEntry{firemon.HostEntry(netip.MustParseAddr(a))}}
	}
	cfg := &firemon.Config{
		Vendor:    firemon.VendorHillstone,
		Addresses: []firemon.Address{host("web", "192.0.2.10"), host("Host_192.0.2.10", "192.0.2.10"), host("db", "192.0.2.20")},
		Rules: []firemon.SecurityRule{
			{ID: "1", Action: firemon.ActionPermit, Destination: []firemon.AddressRef{firemon.NamedAddress("web")}},
			{ID: "2", Action: firemon.ActionPermit, Destination: []firemon.AddressRef{firemon.NamedAddress("Host_192.0.2.10"), firemon.NamedAddress("db")}},
		},
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rep := converge.Analyze(fw, converge.Options{Now: func() time.Time { return time.Unix(0, 0) }})
	if rep.Count(converge.CategoryDuplicateObject) != 1 {
		t.Fatalf("web and Host_192.0.2.10 hold the same host: %+v", rep.Findings)
	}
	f := rep.Findings[len(rep.Findings)-1]
	if f.Tier != converge.TierReview || len(f.Objects) != 2 {
		t.Fatalf("finding %+v", f)
	}
}

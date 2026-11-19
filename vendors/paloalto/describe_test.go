package paloalto_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/traffic"
	"github.com/gatework/firemon/vendors/paloalto"
)

// Object descriptions survive rendering, so a rollback that recreates a
// deleted object restores it exactly.
func TestRender_ObjectDescriptionsReadBack(t *testing.T) {
	t.Parallel()
	addr := firemon.Address{Name: "web", Description: "front end", Entries: []firemon.AddressEntry{firemon.HostEntry(netip.MustParseAddr("192.0.2.10"))}}
	svc := firemon.Service{Name: "app", Description: "app port", Entries: []firemon.ServiceEntry{{Protocol: traffic.ProtocolTCP, Src: traffic.AnyPort, Dst: traffic.Port(8080)}}}
	p := &design.Plan{Kind: design.PlanKindCleanup, Changes: []design.Change{design.AddAddress{Address: addr}, design.AddService{Service: svc}}}
	s, err := paloalto.Renderer{}.Render(p)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := paloalto.New(paloalto.Options{}).Parse(strings.Join(s.Commands, "\n") + "\n")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, a := range cfg.Addresses {
		got[a.Name] = a.Description
	}
	for _, x := range cfg.Services {
		got[x.Name] = x.Description
	}
	if got["web"] != "front end" || got["app"] != "app port" {
		t.Fatalf("descriptions %v from:\n%s", got, strings.Join(s.Commands, "\n"))
	}
}

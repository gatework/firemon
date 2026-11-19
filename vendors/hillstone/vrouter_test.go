package hillstone_test

import (
	"slices"
	"testing"

	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/vendors/hillstone"
)

// TestAddress_FQDNKeepsItsVirtualRouter: the routing context a domain is
// resolved in is read and written back.
func TestAddress_FQDNKeepsItsVirtualRouter(t *testing.T) {
	t.Parallel()
	fw := compileText(t, "address \"cdn\"\n  host \"*.cdn.example.com\" vrouter \"trust-vr\"\nexit\n")
	a := fw.Config().Addresses[0]
	if a.Entries[0].VirtualRouter != "trust-vr" {
		t.Fatalf("entry %+v", a.Entries[0])
	}
	script, err := hillstone.Renderer{}.Render(&design.Plan{Changes: []design.Change{design.AddAddress{Address: a}}, Verified: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(script.Commands, `  host "*.cdn.example.com" vrouter "trust-vr"`) {
		t.Fatalf("commands %q", script.Commands)
	}
}

package firemon_test

import (
	"encoding/json"
	"testing"

	"github.com/gatework/firemon"
)

// TestExternalUsesRoundTrip: snapshots store configurations as JSON; the
// reference enums must read back.
func TestExternalUsesRoundTrip(t *testing.T) {
	t.Parallel()
	in := firemon.Config{Vendor: firemon.VendorHillstone, ExternalUses: []firemon.ExternalUse{{Site: firemon.UseSiteQoS, ID: "qos p", Kind: firemon.ObjectKindSchedule, Name: "nights"}}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out firemon.Config
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.ExternalUses[0] != in.ExternalUses[0] {
		t.Fatalf("got %+v", out.ExternalUses)
	}
}

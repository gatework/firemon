package platform_test

import (
	"errors"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/platform"
)

func TestFor(t *testing.T) {
	t.Parallel()
	for _, v := range platform.Vendors() {
		p, err := platform.For(v, platform.Options{})
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		if p.Vendor != v || p.Parse == nil || p.Render == nil || p.DeployCommands == nil || p.ParseHits == nil || p.HARole == nil {
			t.Fatalf("%s: incomplete platform %+v", v, p)
		}
		target, err := p.MigrationTarget()
		if err != nil || target.Vendor != v || target.Parse == nil {
			t.Fatalf("%s: migration target %+v, %v", v, target, err)
		}
	}
	for _, v := range []firemon.Vendor{firemon.VendorUnset, firemon.Vendor(99)} {
		if _, err := platform.For(v, platform.Options{}); !errors.Is(err, platform.ErrVendor) {
			t.Fatalf("%q: error %v, want ErrVendor", v, err)
		}
	}
}

// HA roles come from the device prompt; PAN-OS can also read the local
// state from "show high-availability state".
func TestPlatform_HARole(t *testing.T) {
	t.Parallel()
	const panState = `Group 1:
  Mode: Active-Passive
  Local Information:
    Version: 1
    State: passive (last 2 days)
  Peer Information:
    Connection status: up
    State: active (last 2 days)
`
	tests := []struct {
		vendor         firemon.Vendor
		prompt, output string
		want           firemon.HARole
	}{
		{firemon.VendorHillstone, "CKG3-FW01(M)# ", "", firemon.HARoleActive},
		{firemon.VendorHillstone, "CKG3-FW02(B)#", "", firemon.HARoleStandby},
		{firemon.VendorHillstone, "CKG3-FW03#", "", firemon.HARoleUnknown},
		{firemon.VendorPaloAlto, "admin@PA-1(active)>", "", firemon.HARoleActive},
		{firemon.VendorPaloAlto, "admin@PA-2(passive)> ", "", firemon.HARoleStandby},
		{firemon.VendorPaloAlto, "admin@PA-2>", panState, firemon.HARoleStandby},
		{firemon.VendorPaloAlto, "admin@PA-3>", "HA not enabled", firemon.HARoleUnknown},
		{firemon.VendorPaloAlto, "admin@PA-4(non-functional)>", "", firemon.HARoleUnknown},
	}
	for _, tt := range tests {
		p, err := platform.For(tt.vendor, platform.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if got := p.HARole(tt.prompt, tt.output); got != tt.want {
			t.Errorf("%s %q: got %q, want %q", tt.vendor, tt.prompt, got, tt.want)
		}
	}
}

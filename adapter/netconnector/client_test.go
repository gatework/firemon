package netconnector_test

import (
	"errors"
	"testing"

	"github.com/gatework/net-connector/connectortest"
	"github.com/gatework/netops/credential"
	"github.com/gatework/netops/secret"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/adapter/netconnector"
)

func TestNew(t *testing.T) {
	t.Parallel()
	parse := func(string) (*firemon.Config, error) { return &firemon.Config{}, nil }
	creds := credential.Static{Username: "admin", Password: secret.New("x")}
	tr := connectortest.NewDialer(t)
	if _, err := netconnector.New(firemon.VendorUnset, "192.0.2.1", tr, creds, 0, 0, parse); !errors.Is(err, netconnector.ErrUnsupportedVendor) {
		t.Fatalf("unset vendor: %v", err)
	}
	if _, err := netconnector.New(firemon.VendorHillstone, "fw1", tr, creds, 0, 0, parse); err == nil {
		t.Fatal("a name is not a device address")
	}
	for v, platform := range map[firemon.Vendor]string{firemon.VendorHillstone: "hillstone", firemon.VendorPaloAlto: "palo_alto"} {
		c, err := netconnector.New(v, "192.0.2.1", tr, creds, 0, 0, parse)
		if err != nil {
			t.Fatal(err)
		}
		if d := c.Device(); d.Mgmt.String() != "192.0.2.1" || d.Platform != platform {
			t.Errorf("device %+v", d)
		}
	}
}

func TestWithVersion(t *testing.T) {
	t.Parallel()
	info := "hostname: pa1\nip-address: 192.0.2.1\nsw-version: 10.2.4\nmodel: PA-3220\n"
	if got := netconnector.WithVersion("set deviceconfig system hostname pa1\n", info); got != "sw-version: 10.2.4\nset deviceconfig system hostname pa1\n" {
		t.Fatalf("got %q", got)
	}
	if got := netconnector.WithVersion("set x\n", "error: unknown command\n"); got != "set x\n" {
		t.Fatalf("no version: got %q", got)
	}
}

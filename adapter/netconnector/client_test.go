package netconnector_test

import (
	"errors"
	"testing"

	"github.com/gatework/net-connector/connector"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/adapter/netconnector"
)

func TestNew(t *testing.T) {
	t.Parallel()
	parse := func(string) (*firemon.Config, error) { return &firemon.Config{}, nil }
	if _, err := netconnector.New(firemon.VendorUnset, connector.ConnectionConfig{}, parse); !errors.Is(err, netconnector.ErrUnsupportedVendor) {
		t.Fatalf("unset vendor: %v", err)
	}
	for _, v := range []firemon.Vendor{firemon.VendorHillstone, firemon.VendorPaloAlto} {
		c, err := netconnector.New(v, connector.ConnectionConfig{Host: "fw1"}, parse)
		if err != nil {
			t.Fatal(err)
		}
		if d := c.Device(); d.Host != "fw1" || d.Platform != v.String() {
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

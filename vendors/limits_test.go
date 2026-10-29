package vendors_test

import (
	"context"
	"errors"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/vendors"
)

func TestAllNativeParsersHonorSelectedLimits(t *testing.T) {
	for _, vendor := range []string{"asa", "srx", "paloalto", "fortinet", "huawei", "hillstone", "netscreen"} {
		t.Run(vendor, func(t *testing.T) {
			_, err := (vendors.Parser{Limits: config.Limits{MaxBytes: 1}}).Parse(context.Background(), config.Source{Text: "long source\n"}, fm.Metadata{Vendor: vendor})
			if !errors.Is(err, config.ErrSource) {
				t.Fatal(err)
			}
		})
	}
	_, err := (vendors.Parser{Limits: config.Limits{MaxBytes: 1}}).Parse(context.Background(), config.Source{Text: "<config/>"}, fm.Metadata{Vendor: "paloalto"})
	if !errors.Is(err, config.ErrSource) {
		t.Fatal(err)
	}
}

func TestRegistryFortinetSelectionDoesNotLeakOtherContext(t *testing.T) {
	raw := "config vdom\n edit blue\n config firewall address\n edit host\n set subnet 192.0.2.1 255.255.255.255\n next\n end\n next\n edit red\n config firewall address\n edit host\n set subnet 198.51.100.1 255.255.255.255\n next\n end\n next\nend\n"
	fw, err := (vendors.Parser{}).Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "synthetic", Vendor: "fortinet", Context: "blue"})
	if err != nil {
		t.Fatal(err)
	}
	a := fw.Address("host")
	if fw.Metadata().Context != "blue" || a == nil || a.Record().Ranges[0].First.String() != "192.0.2.1" {
		t.Fatal("selected context leaked")
	}
}

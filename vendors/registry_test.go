package vendors_test

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/vendors"
)

func TestNativeRegistryParsesSevenVendorsAndExistingAliases(t *testing.T) {
	for _, tc := range []struct {
		name, vendor, fixture string
		complete              bool
	}{
		{"paloalto", "paloalto", "paloalto/testdata/basic.cfg", true},
		{"palo_alto", "paloalto", "paloalto/testdata/basic.cfg", true},
		{"srx", "srx", "srx/testdata/basic.set", true},
		{"huawei", "huawei", "", true},
		{"hillstone", "hillstone", "hillstone/testdata/basic.cfg", false},
		{"fortinet", "fortinet", "fortinet/testdata/basic.conf", true},
		{"netscreen", "netscreen", "netscreen/testdata/basic.set", true},
		{"screenos", "netscreen", "netscreen/testdata/basic.set", true},
		{"asa", "asa", "asa/testdata/basic.cfg", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw := "security-policy\n rule name allow\n  source-address any\n  destination-address any\n  service any\n  action permit\n#\nreturn\n"
			if tc.fixture != "" {
				b, err := os.ReadFile(tc.fixture)
				if err != nil {
					t.Fatal(err)
				}
				raw = string(b)
			}
			var parser deploy.Parser = vendors.Parser{}
			fw, err := parser.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "synthetic", Vendor: tc.name})
			if err != nil {
				t.Fatal(err)
			}
			if fw.Metadata().Vendor != tc.vendor || fw.Metadata().Device != "synthetic" || fw.Export().Raw != raw || len(fw.Rules()) == 0 || fw.Complete() != tc.complete {
				t.Fatalf("native graph/evidence lost: %+v, diagnostics: %+v", fw.Metadata(), fw.Diagnostics())
			}
			r, err := vendors.Renderer(tc.name)
			if err != nil || r == nil {
				t.Fatal("native renderer missing", err)
			}
			if reflect.TypeOf(r).PkgPath() != "github.com/gatework/firemon/vendors/"+tc.vendor {
				t.Fatalf("registry selected another vendor's renderer: %T", r)
			}
		})
	}
}

func TestNativeRegistryUsesSelectedFortinetContext(t *testing.T) {
	raw := "config vdom\nedit root\nconfig firewall address\nedit root-only\nset subnet 192.0.2.1 255.255.255.255\nnext\nend\nnext\nedit tenant\nconfig firewall address\nedit tenant-only\nset subnet 198.51.100.1 255.255.255.255\nnext\nend\nnext\nend\n"
	for _, selected := range []string{"", "tenant"} {
		t.Run("context="+selected, func(t *testing.T) {
			want := selected
			if want == "" {
				want = "root"
			}
			fw, err := (vendors.Parser{}).Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "fw", Vendor: "fortinet", Context: selected})
			if err != nil || !fw.Complete() || fw.Metadata().Context != want || fw.Address(fm.ID(want+"-only")) == nil {
				t.Fatal("wrong VDOM selected", err, fw)
			}
			other := "tenant"
			if want == other {
				other = "root"
			}
			if fw.Address(fm.ID(other+"-only")) != nil {
				t.Fatal("another VDOM leaked into selected graph")
			}
		})
	}
}

func TestNativeRegistryRejectsUnsupportedVendorsAndCancellation(t *testing.T) {
	for _, vendor := range []string{"", "h3c", "topsec", "neteye", "fortinet\npassword"} {
		t.Run(vendor, func(t *testing.T) {
			_, err := (vendors.Parser{}).Parse(context.Background(), config.Source{}, fm.Metadata{Device: "fw", Vendor: vendor})
			if !errors.Is(err, vendors.ErrUnsupported) || strings.Contains(err.Error(), "password") {
				t.Fatal("unsupported vendor accepted or echoed", err)
			}
			if _, err := vendors.Renderer(vendor); !errors.Is(err, vendors.ErrUnsupported) {
				t.Fatal("unsupported renderer accepted", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (vendors.Parser{}).Parse(ctx, config.Source{}, fm.Metadata{Device: "fw", Vendor: "hillstone"}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}

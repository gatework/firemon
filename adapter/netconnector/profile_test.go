package netconnector_test

import (
	"context"
	"errors"
	"io"
	"testing"

	fm "github.com/gatework/firemon"
	adapter "github.com/gatework/firemon/adapter/netconnector"
	"github.com/gatework/go-net-connector/connector"
)

func TestProfileCanonicalVendors(t *testing.T) {
	for _, tc := range []struct{ vendor, profile string }{
		{"paloalto", "palo_alto"}, {"srx", "juniper"}, {"huawei", "huawei"},
		{"hillstone", "hillstone"}, {"fortinet", "fortinet"}, {"netscreen", "netscreen"}, {"asa", "asa"},
	} {
		t.Run(tc.vendor, func(t *testing.T) {
			profile, err := adapter.Profile(tc.vendor)
			if err != nil || profile.Name != tc.profile {
				t.Fatalf("profile=%q, want %q, err=%v", profile.Name, tc.profile, err)
			}
			meta := fm.Metadata{Device: "fw", Vendor: tc.vendor}
			if tc.vendor == "fortinet" {
				meta.Context = "blue"
			}
			names := []string{profile.Name}
			if profile.Name != tc.vendor {
				names = append(names, tc.vendor)
			}
			for _, name := range names {
				t.Run(name, func(t *testing.T) {
					profile.Name = name
					d, err := connector.New(profile, connector.ConnectionConfig{Host: "synthetic"})
					if err != nil {
						t.Fatal(err)
					}
					s, err := adapter.New(d, meta, adapter.Options{})
					if err != nil {
						_ = d.Close()
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = s.Close() })
				})
			}
		})
	}
}

func TestVendorAliasesRejectedBeforeDial(t *testing.T) {
	for _, tc := range []struct{ vendor, alias string }{
		{"paloalto", "palo_alto"}, {"srx", "juniper"}, {"netscreen", "screenos"}, {"asa", "cisco_asa"},
		{"asa", ""}, {"asa", "h3c"}, {"paloalto", "PaloAlto"},
	} {
		t.Run(tc.alias, func(t *testing.T) {
			if _, err := adapter.Profile(tc.alias); !errors.Is(err, adapter.ErrInvalid) {
				t.Fatalf("Profile accepted %q: %v", tc.alias, err)
			}
			profile, err := adapter.Profile(tc.vendor)
			if err != nil {
				t.Fatal(err)
			}
			dials := 0
			opts := []connector.Option{connector.WithTransportFactory(func(context.Context, connector.ConnectionConfig) (io.ReadWriteCloser, error) {
				dials++
				return nil, errors.New("unexpected dial")
			})}
			cfg := connector.ConnectionConfig{Host: "synthetic"}
			d, err := connector.New(profile, cfg, opts...)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = d.Close() })
			meta := fm.Metadata{Device: "fw", Vendor: tc.alias}
			if _, err := adapter.New(d, meta, adapter.Options{}); !errors.Is(err, adapter.ErrInvalid) {
				t.Fatalf("New accepted %q: %v", tc.alias, err)
			}
			f := adapter.Factory{Resolve: func(context.Context, string) (adapter.Target, error) {
				return adapter.Target{Metadata: meta, Connection: cfg, DeviceOptions: opts}, nil
			}}
			if _, err := f.Open(t.Context(), "fw"); !errors.Is(err, adapter.ErrInvalid) {
				t.Fatalf("Open accepted %q: %v", tc.alias, err)
			}
			if _, err := f.OpenReadOnly(t.Context(), "fw"); !errors.Is(err, adapter.ErrInvalid) {
				t.Fatalf("OpenReadOnly accepted %q: %v", tc.alias, err)
			}
			if dials != 0 {
				t.Fatalf("invalid vendor reached transport: %d dials", dials)
			}
		})
	}
}

func TestNewRejectsMismatchedProfile(t *testing.T) {
	for _, tc := range []struct{ vendor, profile string }{
		{"paloalto", "juniper"}, {"srx", "palo_alto"}, {"huawei", "hillstone"},
		{"netscreen", "screenos"}, {"asa", "cisco_asa"},
	} {
		t.Run(tc.vendor+"/"+tc.profile, func(t *testing.T) {
			profile, err := adapter.Profile(tc.vendor)
			if err != nil {
				t.Fatal(err)
			}
			profile.Name = tc.profile
			d, err := connector.New(profile, connector.ConnectionConfig{Host: "synthetic"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = d.Close() })
			if _, err := adapter.New(d, fm.Metadata{Device: "fw", Vendor: tc.vendor}, adapter.Options{}); !errors.Is(err, adapter.ErrInvalid) {
				t.Fatalf("mismatched profile accepted: %v", err)
			}
		})
	}
}

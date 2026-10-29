package netconnector_test

import (
	"context"
	"errors"
	"io"
	"testing"

	fm "github.com/gatework/firemon"
	adapter "github.com/gatework/firemon/adapter/netconnector"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/go-net-connector/connector"
)

func TestNativeContextSelectionIsValidatedBeforeDialAndCapture(t *testing.T) {
	for _, vendor := range []string{"asa", "hillstone", "paloalto", "srx", "huawei", "netscreen", "fortinet"} {
		for _, domain := range []string{"", "blue", "bad;context"} {
			t.Run(vendor+"/"+domain, func(t *testing.T) {
				valid := vendor == "fortinet" && domain == "blue" || vendor != "fortinet" && domain == ""
				metadata := fm.Metadata{Device: "fw", Vendor: vendor, Context: domain}
				profile, err := adapter.Profile(vendor)
				if err != nil {
					t.Fatal(err)
				}
				dials := 0
				options := []connector.Option{connector.WithTransportFactory(func(context.Context, connector.ConnectionConfig) (io.ReadWriteCloser, error) {
					dials++
					return nil, errors.New("unexpected dial")
				})}
				device, err := connector.New(profile, connector.ConnectionConfig{Host: "synthetic"}, options...)
				if err != nil {
					t.Fatal(err)
				}
				session, err := adapter.New(device, metadata, adapter.Options{})
				if (err == nil) != valid {
					t.Errorf("New validity=%v, err=%v", valid, err)
				}
				if session != nil {
					_ = session.Close()
				} else {
					_ = device.Close()
				}
				if valid {
					return
				}
				factory := adapter.Factory{Resolve: func(context.Context, string) (adapter.Target, error) {
					return adapter.Target{Metadata: metadata, Connection: connector.ConnectionConfig{Host: "synthetic"}, DeviceOptions: options}, nil
				}}
				store, err := snapshot.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				parses := 0
				collector := operations.Collector{Store: store, Sessions: factory, Parser: deploy.ParseFunc(func(context.Context, config.Source, fm.Metadata) (*fm.Firewall, error) {
					parses++
					return nil, errors.New("unexpected parse")
				})}
				result, err := collector.Collect(context.Background(), operations.CollectRequest{Device: "fw", PublicationID: "bad-context"})
				if !errors.Is(err, adapter.ErrInvalid) || result.Revision != "" || dials != 0 || parses != 0 {
					t.Fatalf("unselected context reached capture: dials=%d parses=%d result=%+v err=%v", dials, parses, result, err)
				}
				manifest, err := store.Manifest(context.Background())
				if err != nil || len(manifest.Publications) != 0 {
					t.Fatal(manifest, err)
				}
			})
		}
	}
}

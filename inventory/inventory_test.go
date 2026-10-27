package inventory_test

import (
	"context"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/snapshot"
	"net/netip"
	"testing"
)

func TestLocationUsesManifestAndUnknownDeviceCannotDisappear(t *testing.T) {
	ctx := context.Background()
	store, _ := snapshot.Open(t.TempDir())
	for _, name := range []string{"known", "unknown"} {
		d := fm.Data{Metadata: fm.Metadata{Device: name, Vendor: "test"}, Interfaces: []fm.InterfaceRecord{{Object: fm.Object{ID: "eth0"}, Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}}}}
		if name == "unknown" {
			d.Diagnostics = []fm.Diagnostic{{Code: "incomplete"}}
		}
		fw, _ := fm.Seal(d)
		if _, err := store.Publish(ctx, fw, snapshot.PublishOptions{PublicationID: name, Live: true}); err != nil {
			t.Fatal(err)
		}
	}
	r, _ := flow.PrefixRange(netip.MustParsePrefix("192.0.2.128/25"))
	query, _ := flow.NewSet(r)
	result, err := inventory.Locate(ctx, store, query)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || len(result.Unknown) != 1 || result.Unknown[0] != "unknown" || len(result.Hits) != 1 || result.Hits[0].Device != "known" {
		t.Fatal(result)
	}
	if !result.Hits[0].Addresses.Contains(query) {
		t.Fatal("partial subnet location lost")
	}
}

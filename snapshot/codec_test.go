package snapshot_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/snapshot"
)

func graph(t *testing.T, device, raw string, complete bool) *fm.Firewall {
	t.Helper()
	d := fm.Data{Metadata: fm.Metadata{Device: device, Vendor: "hillstone", ParserVersion: "1"}, Raw: raw,
		Zones: []fm.ZoneRecord{{Object: fm.Object{ID: "trust"}}}, Interfaces: []fm.InterfaceRecord{{Object: fm.Object{ID: "eth0"}, Zone: "trust", Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}}},
		StaticNATs:  []fm.StaticNATRecord{{Object: fm.Object{ID: "static"}, Interface: "eth0"}},
		DynamicNATs: []fm.DynamicNATRecord{{Object: fm.Object{ID: "dynamic"}, Interface: "eth0", SourceMode: fm.InterfaceIP, DestinationMode: fm.NoTranslation}},
	}
	if !complete {
		d.Diagnostics = []fm.Diagnostic{{Code: "unparsed", Message: "unrecognized statement"}}
	}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}
func TestGobRestoresTypedNATAndSharedGraphWithoutParsingRaw(t *testing.T) {
	original := graph(t, "fw", "this raw is deliberately not a configuration", true)
	data := original.Export()
	host := netip.MustParseAddr("192.0.2.10")
	data.Addresses = []fm.AddressRecord{{Object: fm.Object{ID: "host"}, Ranges: []flow.AddressRange{{First: host, Last: host}}}}
	data.StaticNATs[0].Match.Sources = []fm.AddressRef{{Kind: fm.AddressObject, ID: "host"}}
	data.DynamicNATs[0].Match.Sources = []fm.AddressRef{{Kind: fm.AddressObject, ID: "host"}}
	original, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := snapshot.Encode(&buf, original); err != nil {
		t.Fatal(err)
	}
	fw, err := snapshot.Decode(bytes.NewReader(buf.Bytes()), snapshot.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if fw.StaticNAT("static").Interface() != fw.DynamicNAT("dynamic").Interface() || fw.Interface("eth0").Zone() != fw.Zone("trust") {
		t.Fatal("gob lost shared graph identity")
	}
	if fw.StaticNAT("static").Match().Sources()[0] != fw.Address("host") || fw.DynamicNAT("dynamic").Match().Sources()[0] != fw.Address("host") {
		t.Fatal("NAT match references not shared after gob load")
	}
	if fw.Export().Raw != original.Export().Raw || fw.SemanticDigest() != original.SemanticDigest() {
		t.Fatal("roundtrip changed evidence")
	}
}
func TestGobRejectsCorruptionVersionsAndOversize(t *testing.T) {
	var buf bytes.Buffer
	_ = snapshot.Encode(&buf, graph(t, "fw", "raw", true))
	data := buf.Bytes()
	for _, tc := range []struct {
		name string
		edit func([]byte)
	}{{"checksum", func(b []byte) { b[len(b)-1] ^= 1 }}, {"version", func(b []byte) { b[9] = 99 }}, {"length", func(b []byte) { b[15] = 255 }}} {
		t.Run(tc.name, func(t *testing.T) {
			b := bytes.Clone(data)
			tc.edit(b)
			if _, err := snapshot.Decode(bytes.NewReader(b), snapshot.DefaultMaxBytes); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
	if _, err := snapshot.Decode(bytes.NewReader(data), 8); err == nil {
		t.Fatal("size limit ignored")
	}
}

func TestGobRejectsVersionSevenWithoutInterfaceSelectionSemantics(t *testing.T) {
	var buf bytes.Buffer
	if err := snapshot.Encode(&buf, graph(t, "fw", "raw", true)); err != nil {
		t.Fatal(err)
	}
	// Version 7 could persist a complete PAN graph with a widened interface
	// allocation or a route merged across virtual routers. Loading must not
	// endorse it or silently reparse the retained configuration.
	old := bytes.Clone(buf.Bytes())
	old[10], old[11] = 0, 7
	if _, err := snapshot.Decode(bytes.NewReader(old), snapshot.DefaultMaxBytes); !errors.Is(err, snapshot.ErrFormat) {
		t.Fatal("obsolete native semantics accepted", err)
	}
}

func TestGobRejectsVersionEightWithoutExplicitVIPReferences(t *testing.T) {
	var buf bytes.Buffer
	if err := snapshot.Encode(&buf, graph(t, "fw", "raw", true)); err != nil {
		t.Fatal(err)
	}
	old := bytes.Clone(buf.Bytes())
	old[10], old[11] = 0, 8
	if _, err := snapshot.Decode(bytes.NewReader(old), snapshot.DefaultMaxBytes); !errors.Is(err, snapshot.ErrFormat) {
		t.Fatal("implicit VIP graph semantics accepted", err)
	}
}

func TestGobRestoresExplicitVIPReferencesAndTypedPointerIdentity(t *testing.T) {
	public := netip.MustParseAddr("198.51.100.20")
	private := netip.MustParseAddr("192.0.2.20")
	mapping := fm.Mapping{Original: flow.AddressRange{First: public, Last: public}, Translated: flow.AddressRange{First: private, Last: private}, Mode: fm.Offset}
	d := fm.Data{
		Metadata: fm.Metadata{Device: "synthetic", Vendor: "fortinet", Context: "root"},
		Addresses: []fm.AddressRecord{
			{Object: fm.Object{ID: "static-address", Scope: "root"}, Ranges: []flow.AddressRange{mapping.Original}, VIP: fm.NATRef{Kind: fm.StaticNATObject, ID: "same-native-id"}},
			{Object: fm.Object{ID: "port-address", Scope: "root"}, Ranges: []flow.AddressRange{mapping.Original}, VIP: fm.NATRef{Kind: fm.DynamicNATObject, ID: "same-native-id"}},
			{Object: fm.Object{ID: "vip:ordinary", Name: "vip", Scope: "root"}, Ranges: []flow.AddressRange{mapping.Original}},
		},
		StaticNATs: []fm.StaticNATRecord{
			{Object: fm.Object{ID: "same-native-id", Scope: "root"}, Destination: []fm.Mapping{mapping}},
			{Object: fm.Object{ID: "source-map", Name: "unrelated-native-name", Scope: "root"}, SourceVIP: fm.AddressRef{Kind: fm.AddressObject, ID: "static-address"}, Source: []fm.Mapping{{Original: mapping.Translated, Translated: mapping.Original, Mode: fm.Offset}}},
		},
		DynamicNATs: []fm.DynamicNATRecord{{Object: fm.Object{ID: "same-native-id", Scope: "root"}, SourceMode: fm.NoTranslation, DestinationMode: fm.StaticIP, Destination: []fm.Mapping{mapping}}},
	}
	original, err := fm.Seal(d)
	if err != nil || !original.Complete() {
		t.Fatal(original, err)
	}
	var buf bytes.Buffer
	if err := snapshot.Encode(&buf, original); err != nil {
		t.Fatal(err)
	}
	if version := uint16(buf.Bytes()[10])<<8 | uint16(buf.Bytes()[11]); version != 9 {
		t.Fatalf("semantic version = %d, want 9", version)
	}
	fw, err := snapshot.Decode(&buf, snapshot.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !fw.Complete() || fw.SemanticDigest() != original.SemanticDigest() {
		t.Fatal("VIP graph roundtrip changed semantics", fw.Diagnostics())
	}
	if fw.Address("static-address").VIPStaticNAT() != fw.StaticNAT("same-native-id") || fw.Address("port-address").VIPDynamicNAT() != fw.DynamicNAT("same-native-id") || fw.StaticNAT("source-map").SourceVIP() != fw.Address("static-address") {
		t.Fatal("VIP pointers were not restored from the typed references")
	}
	if a := fw.Address("vip:ordinary"); a.Record().VIP != (fm.NATRef{}) || a.VIPStaticNAT() != nil || a.VIPDynamicNAT() != nil {
		t.Fatal("snapshot inferred VIP semantics from native name or ID")
	}
}
func TestStoreCASDraftsAndLiveIncompleteInvalidateCurrent(t *testing.T) {
	ctx := context.Background()
	store, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Publish(ctx, graph(t, "fw", "v1", true), snapshot.PublishOptions{PublicationID: "one"})
	if err != nil {
		t.Fatal(err)
	}
	same, err := store.Publish(ctx, graph(t, "fw", "v1", true), snapshot.PublishOptions{PublicationID: "one"})
	if err != nil || same.Revision != first.Revision {
		t.Fatal(same, err)
	}
	if _, err := store.Publish(ctx, graph(t, "fw", "v2", true), snapshot.PublishOptions{PublicationID: "two"}); !errors.Is(err, snapshot.ErrConflict) {
		t.Fatal("stale publish", err)
	}
	draft, err := store.Publish(ctx, graph(t, "fw", "bad draft", false), snapshot.PublishOptions{Expected: first.Revision, PublicationID: "draft"})
	if err != nil || !draft.Archived {
		t.Fatal(draft, err)
	}
	fw, _, err := store.Current(ctx, "fw")
	if err != nil || fw.Export().Raw != "v1" {
		t.Fatal("offline draft displaced current", err)
	}
	_, err = store.Publish(ctx, graph(t, "fw", "bad live", false), snapshot.PublishOptions{Expected: first.Revision, PublicationID: "live", Live: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Current(ctx, "fw"); !errors.Is(err, snapshot.ErrUnavailable) {
		t.Fatal("stale current remained available", err)
	}
	if _, err := store.Load(ctx, first.Revision); err != nil {
		t.Fatal("historical graph lost", err)
	}
}
func TestReservationPersistsAcrossStoreInstancesAndNeverExpires(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	a, _ := snapshot.Open(dir)
	first, err := a.Publish(ctx, graph(t, "fw", "v1", true), snapshot.PublishOptions{PublicationID: "one"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Reserve(ctx, "fw", first.Revision, "token"); err != nil {
		t.Fatal(err)
	}
	b, _ := snapshot.Open(dir)
	if _, _, err := b.Current(ctx, "fw"); !errors.Is(err, snapshot.ErrUnavailable) {
		t.Fatal("cross-process reservation ignored", err)
	}
	if _, err := b.Publish(ctx, graph(t, "fw", "v2", true), snapshot.PublishOptions{Expected: first.Revision, PublicationID: "two"}); !errors.Is(err, snapshot.ErrReserved) {
		t.Fatal("reservation bypass", err)
	}
	if _, err := b.Publish(ctx, graph(t, "fw", "v2", true), snapshot.PublishOptions{Expected: first.Revision, PublicationID: "two", Reservation: "token", Live: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Current(ctx, "fw"); err != nil {
		t.Fatal("publication did not release reservation", err)
	}
}

func TestConcurrentPublishHasExactlyOneCASWinner(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, _ := snapshot.Open(dir)
	first, err := store.Publish(ctx, graph(t, "fw", "base", true), snapshot.PublishOptions{PublicationID: "base"})
	if err != nil {
		t.Fatal(err)
	}
	candidates := make([]*fm.Firewall, 8)
	for i := range candidates {
		candidates[i] = graph(t, "fw", fmt.Sprintf("next-%d", i), true)
	}
	results := make(chan error, 8)
	for i, fw := range candidates {
		go func() {
			other, err := snapshot.Open(dir)
			if err == nil {
				_, err = other.Publish(ctx, fw, snapshot.PublishOptions{Expected: first.Revision, PublicationID: fmt.Sprintf("publish-%d", i)})
			}
			results <- err
		}()
	}
	wins := 0
	for range candidates {
		err := <-results
		if err == nil {
			wins++
		} else if !errors.Is(err, snapshot.ErrConflict) {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatalf("CAS winners %d", wins)
	}
}

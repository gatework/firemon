package firemon_test

import (
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

func vipData() fm.Data {
	match := fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}
	public := rng("198.51.100.10", "198.51.100.10")
	private := rng("192.0.2.10", "192.0.2.10")
	return fm.Data{
		Metadata: fm.Metadata{Device: "synthetic", Vendor: "fortinet", Context: "root"},
		Addresses: []fm.AddressRecord{
			{Object: fm.Object{ID: "public-static", Name: "native-static", Scope: "root"}, Ranges: []flow.Range{public}, VIP: fm.NATRef{Kind: fm.StaticNATObject, ID: "shared-native-id"}},
			{Object: fm.Object{ID: "public-port", Name: "native-port", Scope: "root"}, Ranges: []flow.Range{public}, VIP: fm.NATRef{Kind: fm.DynamicNATObject, ID: "shared-native-id"}},
			{Object: fm.Object{ID: "vip:ordinary", Name: "vip", Scope: "root"}, Ranges: []flow.Range{public}},
		},
		StaticNATs: []fm.StaticNATRecord{
			{Object: fm.Object{ID: "shared-native-id", Scope: "root"}, Match: match, Destination: []fm.Mapping{{Original: public, Translated: private, Mode: fm.Offset}}},
			{Object: fm.Object{ID: "source-map", Name: "unrelated-name", Scope: "root"}, Match: match, Source: []fm.Mapping{{Original: private, Translated: public, Mode: fm.Offset}}, SourceVIP: fm.AddressRef{Kind: fm.AddressObject, ID: "public-static"}},
		},
		DynamicNATs: []fm.DynamicNATRecord{{Object: fm.Object{ID: "shared-native-id", Scope: "root"}, Match: match, SourceMode: fm.NoTranslation, DestinationMode: fm.StaticIP, Destination: []fm.Mapping{{Original: public, Translated: private, Mode: fm.Offset}}}},
	}
}

func TestSealVIPReferencesResolveConcreteCatalogsAndRemainImmutable(t *testing.T) {
	d := vipData()
	fw, err := fm.Seal(d)
	if err != nil || !fw.Complete() {
		t.Fatal(fw, err)
	}
	if a := fw.Address("public-static"); a.VIPStaticNAT() != fw.StaticNAT("shared-native-id") || a.VIPDynamicNAT() != nil {
		t.Fatal("static VIP did not bind its concrete catalog")
	}
	if a := fw.Address("public-port"); a.VIPDynamicNAT() != fw.DynamicNAT("shared-native-id") || a.VIPStaticNAT() != nil {
		t.Fatal("port VIP did not bind its concrete catalog")
	}
	if fw.StaticNAT("source-map").SourceVIP() != fw.Address("public-static") {
		t.Fatal("source mapping did not retain shared VIP address identity")
	}
	if a := fw.Address("vip:ordinary"); a.VIPStaticNAT() != nil || a.VIPDynamicNAT() != nil || a.Record().VIP != (fm.NATRef{}) {
		t.Fatal("ordinary native name or ID became a VIP")
	}
	d.Addresses[0].VIP.ID = "changed"
	d.StaticNATs[1].SourceVIP.ID = "changed"
	exported := fw.Export()
	exported.Addresses[0].VIP.ID = "changed"
	exported.StaticNATs[1].SourceVIP.ID = "changed"
	if fw.Address("public-static").Record().VIP.ID != "shared-native-id" || fw.StaticNAT("source-map").Record().SourceVIP.ID != "public-static" {
		t.Fatal("reference records leaked mutability")
	}
}

func TestSealInvalidVIPReferencesRemainExplicitAndIncomplete(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*fm.Data)
	}{
		{"missing-target", func(d *fm.Data) { d.Addresses[0].VIP.ID = "missing" }},
		{"wrong-kind", func(d *fm.Data) { d.Addresses[0].VIP.Kind = fm.AddressObject }},
		{"missing-id", func(d *fm.Data) { d.Addresses[0].VIP.ID = "" }},
		{"missing-kind", func(d *fm.Data) { d.Addresses[0].VIP.Kind = fm.UnknownObject }},
		{"cross-scope", func(d *fm.Data) { d.StaticNATs[0].Scope = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := vipData()
			tc.edit(&d)
			fw, err := fm.Seal(d)
			if err != nil {
				t.Fatal(err)
			}
			a := fw.Address("public-static")
			if fw.Complete() || a.Record().VIP == (fm.NATRef{}) || a.VIPStaticNAT() != nil || a.VIPDynamicNAT() != nil || fw.StaticNAT("source-map").SourceVIP() != nil {
				t.Fatal("invalid VIP link became ordinary or a resolved target", fw.Diagnostics())
			}
		})
	}
}

func TestSealInvalidVIPSourceReferencesRemainIncomplete(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*fm.Data)
	}{
		{"missing-address", func(d *fm.Data) { d.StaticNATs[1].SourceVIP.ID = "missing" }},
		{"wrong-kind", func(d *fm.Data) { d.StaticNATs[1].SourceVIP.Kind = fm.AddressGroupObject }},
		{"ordinary-address", func(d *fm.Data) { d.StaticNATs[1].SourceVIP.ID = "vip:ordinary" }},
		{"cross-scope", func(d *fm.Data) { d.StaticNATs[1].Scope = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := vipData()
			tc.edit(&d)
			fw, err := fm.Seal(d)
			if err != nil {
				t.Fatal(err)
			}
			if fw.Complete() || fw.StaticNAT("source-map").SourceVIP() != nil {
				t.Fatal("invalid source VIP link accepted", fw.Diagnostics())
			}
		})
	}
}

func TestVIPReferencesParticipateInSemanticDigest(t *testing.T) {
	d := vipData()
	a, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	d.StaticNATs[1].SourceVIP.ID = "public-port"
	b, err := fm.Seal(d)
	if err != nil || a.SemanticDigest() == b.SemanticDigest() {
		t.Fatal("source VIP association missing from digest", err)
	}
	d.Addresses[0].VIP.Kind = fm.DynamicNATObject
	c, err := fm.Seal(d)
	if err != nil || b.SemanticDigest() == c.SemanticDigest() {
		t.Fatal("typed destination VIP association missing from digest", err)
	}
}

package netscreen_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
)

func TestMIPVIPAndPolicyNATKeepNativeTypesAndOwnership(t *testing.T) {
	fw := parse(t, fixture(t, "nat"))
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	if len(fw.StaticNATs()) != 1 || len(fw.DynamicNATs()) != 3 || len(fw.NATPools()) != 2 {
		t.Fatal("typed NAT catalogs", len(fw.StaticNATs()), len(fw.DynamicNATs()), len(fw.NATPools()))
	}
	nat := fw.DynamicNAT("policy:12")
	if nat == nil || nat.Rule() != fw.Rule("12") || nat.Record().Rule != "12" || nat.SourcePool() == nil {
		t.Fatal("lost policy/pool ownership", nat)
	}
	var buf bytes.Buffer
	if err := snapshot.Encode(&buf, fw); err != nil {
		t.Fatal(err)
	}
	restored, err := snapshot.Decode(&buf, snapshot.DefaultMaxBytes)
	if err != nil || restored.DynamicNAT("policy:12").Rule() != restored.Rule("12") || restored.SemanticDigest() != fw.SemanticDigest() {
		t.Fatal("snapshot rule identity", err)
	}
	for _, tc := range []struct {
		src, dst, from, to, wantSrc, wantDst string
		port, wantPort                       uint16
		kind                                 fm.Kind
		reverse, possible                    bool
	}{
		{"203.0.113.5/32", "198.51.100.60/32", "Untrust", "Trust", "203.0.113.5", "192.0.2.60", 443, 443, fm.StaticNATObject, false, false},
		{"192.0.2.60/32", "203.0.113.5/32", "Trust", "Untrust", "198.51.100.60", "203.0.113.5", 443, 443, fm.StaticNATObject, true, false},
		{"203.0.113.5/32", "198.51.100.70/32", "Untrust", "Trust", "203.0.113.5", "192.0.2.70", 8443, 443, fm.DynamicNATObject, false, false},
		{"203.0.113.5/32", "203.0.113.100/32", "Untrust", "Trust", "203.0.113.5", "192.0.2.80", 80, 8080, fm.DynamicNATObject, false, false},
		{"192.0.2.20/32", "203.0.113.5/32", "Trust", "Untrust", "198.51.100.100", "203.0.113.5", 443, 443, fm.DynamicNATObject, false, true},
	} {
		q := policy.Request{Traffic: traffic(t, tc.src, tc.dst, 6, 12345, tc.port), FromZone: fm.ID(tc.from), ToZone: fm.ID(tc.to)}
		r, err := (policy.Engine{}).QueryNAT(context.Background(), fw, q)
		if err != nil || !r.Complete || len(r.Relations) != 1 || !r.Unknown.Empty() || !r.Unmatched.Empty() {
			t.Fatal(tc, r, err)
		}
		n := r.Relations[0]
		b := n.Translated.Boxes()
		if n.Kind != tc.kind || n.Steps[0].Reverse != tc.reverse || n.PossibleAllocation != tc.possible || len(b) != 1 || b[0].Source.First.String() != tc.wantSrc || b[0].Destination.First.String() != tc.wantDst || b[0].DestinationPort.Low != tc.wantPort || b[0].SourcePort != (flow.Interval{Low: 12345, High: 12345}) {
			t.Fatal(tc, n)
		}
	}
}

func TestPolicyNATCannotSkipDenyPlainPermitOrUnknown(t *testing.T) {
	raw := fixture(t, "nat")
	for _, host := range []string{"192.0.2.10/32", "192.0.2.11/32"} {
		fw := parse(t, raw)
		q := policy.Request{Traffic: traffic(t, host, "203.0.113.5/32", 6, 12345, 443), FromZone: "Trust", ToZone: "Untrust"}
		r, err := (policy.Engine{}).QueryNAT(context.Background(), fw, q)
		if err != nil || !r.Complete || len(r.Relations) != 0 || r.Unmatched.Empty() {
			t.Fatal("later NAT bypassed earlier policy", host, r, err)
		}
	}
	fw := parse(t, strings.ReplaceAll(raw, "blocked Any ANY deny", "missing Any ANY deny"))
	q := policy.Request{Traffic: traffic(t, "192.0.2.20/32", "203.0.113.5/32", 6, 12345, 443), FromZone: "Trust", ToZone: "Untrust"}
	r, err := (policy.Engine{}).QueryNAT(context.Background(), fw, q)
	if err != nil || r.Complete || len(r.Relations) != 0 || r.Unknown.Empty() {
		t.Fatal("unknown early policy skipped", r, err)
	}
}

func TestDIPPortTranslationAndPolicyContinuation(t *testing.T) {
	raw := strings.ReplaceAll(fixture(t, "nat"), "Any Any ANY nat src dip-id 4 permit\nexit", "Any Any ANY permit\nset nat src dip-id 5\nexit")
	fw := parse(t, raw)
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	q := policy.Request{Traffic: traffic(t, "192.0.2.20/32", "203.0.113.5/32", 6, 12345, 443), FromZone: "Trust", ToZone: "Untrust"}
	r, err := (policy.Engine{}).QueryNAT(context.Background(), fw, q)
	if err != nil || !r.Complete || len(r.Relations) != 1 || !r.Relations[0].PossibleAllocation || r.Relations[0].Exact {
		t.Fatal(r, err)
	}
	b := r.Relations[0].Translated.Boxes()[0]
	if b.Source.First.String() != "198.51.100.110" || b.Source.Last.String() != "198.51.100.113" || b.SourcePort != (flow.Interval{Low: 1024, High: 65535}) {
		t.Fatal(b)
	}
}

func TestPolicyOwnedNATRejectsMissingOrChangedOwner(t *testing.T) {
	fw := parse(t, fixture(t, "nat"))
	for _, changed := range []bool{false, true} {
		d := fw.Export()
		for i := range d.DynamicNATs {
			if d.DynamicNATs[i].Rule == "12" {
				if changed {
					d.DynamicNATs[i].Match.AnyService = false
					d.DynamicNATs[i].Match.Services = []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "web"}}
				} else {
					d.DynamicNATs[i].Rule = "missing"
				}
			}
		}
		damaged, err := fm.Seal(d)
		if err != nil {
			t.Fatal(err)
		}
		if damaged.Complete() {
			t.Fatal("policy/NAT ownership became inconsistent")
		}
	}
}

func TestAmbiguousDIPInterfaceAndMalformedNATStayUnknown(t *testing.T) {
	for _, extra := range []string{
		"set interface ethernet0/3 zone Untrust\nset interface ethernet0/3 ip 203.0.113.1/24\n",
		"set interface ethernet0/2 dip 4 shift-from 192.0.2.20 to 198.51.100.100 198.51.100.103\n",
		"set interface ethernet0/2 mip 198.51.100.60 host 192.0.2.61\n",
	} {
		fw := parse(t, fixture(t, "nat")+extra)
		q := policy.Request{Traffic: traffic(t, "192.0.2.20/32", "203.0.113.5/32", 6, 12345, 443), FromZone: "Trust", ToZone: "Untrust"}
		r, err := (policy.Engine{}).QueryNAT(context.Background(), fw, q)
		if err == nil && (r.Complete || r.Unknown.Empty()) {
			t.Fatal("unproven interface/NAT semantics", extra, r)
		}
	}
}

package policy_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func migrationData(vendor string) fm.Data {
	return fm.Data{
		Metadata: fm.Metadata{Device: "synthetic-" + vendor, Vendor: vendor, Software: "5.5R8"},
		Zones:    []fm.ZoneRecord{{Object: fm.Object{ID: "inside"}}, {Object: fm.Object{ID: "outside"}}},
		Interfaces: []fm.InterfaceRecord{
			{Object: fm.Object{ID: "ingress"}, Zone: "inside", Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.254/24")}},
			{Object: fm.Object{ID: "egress"}, Zone: "outside", Addresses: []netip.Prefix{netip.MustParsePrefix("203.0.113.254/24")}},
		},
		Routes:     []fm.RouteRecord{{Object: fm.Object{ID: "default"}, Destination: netip.MustParsePrefix("0.0.0.0/0"), Interface: "egress"}},
		Rules:      []fm.RuleRecord{{Object: fm.Object{ID: "permit"}, RuleSet: "security", Match: anyMatch(), Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Known}},
		StaticNATs: []fm.StaticNATRecord{{Object: fm.Object{ID: "snat"}, Match: anyMatch(), Source: []fm.Mapping{{Original: rangeOf("192.0.2.0/31"), Translated: rangeOf("203.0.113.0/31"), Mode: fm.Offset}}}},
	}
}

func migrationGraph(t *testing.T, data fm.Data) *fm.Firewall {
	t.Helper()
	fw, err := fm.Seal(data)
	if err != nil || !fw.Complete() {
		t.Fatalf("invalid migration fixture: %v, %v", err, fw)
	}
	return fw
}

func migrationRequest(t *testing.T) policy.PacketRequest {
	return policy.PacketRequest{Request: policy.Request{Traffic: traffic(t, "192.0.2.0/31", "198.51.100.10/32"), FromZone: "inside", ToZone: "outside", EgressInterface: "egress", At: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)}}
}

func TestPacketEquivalencePreservesCrossVendorSNATWithoutNativeIDs(t *testing.T) {
	source := migrationGraph(t, migrationData("paloalto"))
	targetData := migrationData("hillstone")
	targetData.StaticNATs[0].ID = "translated-object"
	targetData.Rules[0].ID = "new-policy"
	targetData.Zones[0].ID, targetData.Zones[1].ID = "trust", "untrust"
	targetData.Interfaces[0].Zone, targetData.Interfaces[1].Zone = "trust", "untrust"
	target := migrationGraph(t, targetData)
	a, b := migrationRequest(t), migrationRequest(t)
	b.FromZone, b.ToZone = "trust", "untrust"
	proof, err := (policy.Engine{}).EquivalentPacketEffects(t.Context(), source, target, a, b)
	if err != nil || proof.SourceDigest != source.SemanticDigest() || proof.TargetDigest != target.SemanticDigest() || proof.Partitions != 1 || proof.SourcePaths != 1 || proof.TargetPaths != 1 {
		t.Fatal("cross-vendor original-to-translated relation was not proved", proof, err)
	}
}

func TestPacketEquivalenceRejectsEqualTranslatedUnionWithDifferentCorrelation(t *testing.T) {
	a, b := migrationData("paloalto"), migrationData("hillstone")
	a.StaticNATs[0].Source = []fm.Mapping{
		{Original: rangeOf("192.0.2.0/32"), Translated: rangeOf("203.0.113.0/32"), Mode: fm.Offset},
		{Original: rangeOf("192.0.2.1/32"), Translated: rangeOf("203.0.113.1/32"), Mode: fm.Offset},
	}
	b.StaticNATs[0].Source = []fm.Mapping{
		{Original: rangeOf("192.0.2.0/32"), Translated: rangeOf("203.0.113.1/32"), Mode: fm.Offset},
		{Original: rangeOf("192.0.2.1/32"), Translated: rangeOf("203.0.113.0/32"), Mode: fm.Offset},
	}
	source, target := migrationGraph(t, a), migrationGraph(t, b)
	q := migrationRequest(t)
	left, err := (policy.Engine{}).QueryPacket(t.Context(), source, q)
	if err != nil {
		t.Fatal(err)
	}
	right, err := (policy.Engine{}).QueryPacket(t.Context(), target, q)
	if err != nil {
		t.Fatal(err)
	}
	if same, err := left.Paths[0].NAT.Translated.Equal(right.Paths[0].NAT.Translated, 4096); err != nil || !same {
		t.Fatal("fixture does not have equal output unions", err)
	}
	if _, err := (policy.Engine{}).EquivalentPacketEffects(t.Context(), source, target, q, q); !errors.Is(err, policy.ErrNotEquivalent) {
		t.Fatal("translated union hid a swapped original-to-output relation", err)
	}
}

func dynamicMigrationData(vendor string) fm.Data {
	d := migrationData(vendor)
	d.StaticNATs = nil
	d.NATPools = []fm.NATPoolRecord{{Object: fm.Object{ID: "pool"}, Ranges: []flow.AddressRange{rangeOf("203.0.113.0/31")}}}
	d.DynamicNATs = []fm.DynamicNATRecord{{Object: fm.Object{ID: "allocation"}, Match: anyMatch(), SourceMode: fm.DynamicIPPort, DestinationMode: fm.NoTranslation, SourcePool: "pool", Order: fm.NATOrder{Section: "snat"}}}
	return d
}

func TestPacketEquivalenceRetainsDynamicModesPoolsAndPorts(t *testing.T) {
	q := migrationRequest(t)
	for _, test := range []string{"renamed-pool", "allocation-mode", "pool-ports", "selected-interface-address"} {
		t.Run(test, func(t *testing.T) {
			a, b := dynamicMigrationData("paloalto"), dynamicMigrationData("hillstone")
			b.NATPools[0].ID, b.DynamicNATs[0].SourcePool = "target-pool", "target-pool"
			switch test {
			case "allocation-mode":
				// The request covers every source port, so these modes have the
				// same output union despite different allocation guarantees.
				b.DynamicNATs[0].SourceMode = fm.DynamicIP
			case "pool-ports":
				b.NATPools[0].Ports = flow.Interval{Low: 1024, High: 2000}
			case "selected-interface-address":
				for _, d := range []*fm.Data{&a, &b} {
					d.NATPools = nil
					d.DynamicNATs[0].SourcePool = ""
					d.DynamicNATs[0].SourceMode = fm.InterfaceIP
					d.DynamicNATs[0].Interface = "egress"
				}
				b.Interfaces[1].Addresses = []netip.Prefix{netip.MustParsePrefix("203.0.113.253/24")}
			}
			source, target := migrationGraph(t, a), migrationGraph(t, b)
			_, err := (policy.Engine{}).EquivalentPacketEffects(t.Context(), source, target, q, q)
			if test == "renamed-pool" {
				if err != nil {
					t.Fatal("resolved pool lost cross-vendor identity", err)
				}
			} else if !errors.Is(err, policy.ErrNotEquivalent) {
				t.Fatal("allocation semantics were erased", err)
			}
		})
	}
}

func TestPacketEquivalenceRejectsChangedPolicyOrMissingEvidence(t *testing.T) {
	q := migrationRequest(t)
	source := migrationGraph(t, migrationData("paloalto"))
	for _, test := range []string{"action", "logging", "unknown-logging", "unknown-route", "wrong-egress", "missing-post-zone"} {
		t.Run(test, func(t *testing.T) {
			d := migrationData("hillstone")
			targetRequest := q
			switch test {
			case "action":
				d.Rules[0].Action = fm.Drop
			case "logging":
				d.Rules[0].LogStart = fm.Known
			case "unknown-logging":
				d.Rules[0].Log = fm.Unknown
			case "unknown-route":
				d.Routes = nil
			case "wrong-egress":
				targetRequest.EgressInterface = "ingress"
			case "missing-post-zone":
				targetRequest.ToZone = ""
			}
			if _, err := (policy.Engine{}).EquivalentPacketEffects(t.Context(), source, migrationGraph(t, d), q, targetRequest); !errors.Is(err, policy.ErrNotEquivalent) {
				t.Fatal("unproved native effect was accepted", err)
			}
		})
	}
}

func TestPacketEquivalencePreflightsNestedWorkRegionsAndCancellation(t *testing.T) {
	d := migrationData("paloalto")
	d.Rules[0].Spans = make([]fm.Span, 1000)
	fw := migrationGraph(t, d)
	q := migrationRequest(t)
	if _, err := (policy.Engine{Limits: policy.Limits{MaxVisits: 50}}).EquivalentPacketEffects(t.Context(), fw, fw, q, q); !errors.Is(err, policy.ErrBudget) {
		t.Fatal("nested declaration copying escaped preflight", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := (policy.Engine{}).EquivalentPacketEffects(ctx, fw, fw, q, q); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled packet proof continued", err)
	}
	first := q.Traffic.Regions()[0]
	second := first
	second.Destination = rangeOf("198.51.100.20/32")
	q.Traffic, _ = flow.NewTraffic(2, first, second)
	if _, err := (policy.Engine{Limits: policy.Limits{MaxRegions: 1}}).EquivalentPacketEffects(t.Context(), fw, fw, q, q); !errors.Is(err, policy.ErrBudget) {
		t.Fatal("caller region limit was applied after expansion", err)
	}
}

func TestPacketEquivalenceRejectsReverseNATAndAmbiguousPolicyProjection(t *testing.T) {
	q := migrationRequest(t)
	data := migrationData("hillstone")
	data.StaticNATs[0].Bidirectional = true
	q.Traffic = traffic(t, "198.51.100.10/32", "203.0.113.0/31")
	fw := migrationGraph(t, data)
	if _, err := (policy.Engine{}).EquivalentPacketEffects(t.Context(), fw, fw, q, q); !errors.Is(err, policy.ErrNAT) {
		t.Fatal("reverse packet relation was silently normalized", err)
	}

	data = migrationData("paloalto")
	data.StaticNATs[0].Source = nil
	data.StaticNATs[0].Destination = []fm.Mapping{
		{Original: rangeOf("198.51.100.10/32"), Translated: rangeOf("198.51.100.11/32"), Mode: fm.Offset},
		{Original: rangeOf("198.51.100.11/32"), Translated: rangeOf("198.51.100.10/32"), Mode: fm.Offset},
	}
	data.Addresses = []fm.AddressRecord{{Object: fm.Object{ID: "one-destination"}, Ranges: []flow.AddressRange{rangeOf("198.51.100.10/32")}}}
	first := data.Rules[0]
	first.ID, first.Position = "first", 1
	first.Match.AnyDestination = false
	first.Match.Destinations = []fm.AddressRef{{Kind: fm.AddressObject, ID: "one-destination"}}
	second := data.Rules[0]
	second.ID, second.Position, second.LogStart = "second", 2, fm.Known
	data.Rules = []fm.RuleRecord{first, second}
	q = migrationRequest(t)
	q.Traffic = traffic(t, "192.0.2.0/31", "198.51.100.10/31")
	fw = migrationGraph(t, data)
	if _, err := (policy.Engine{}).EquivalentPacketEffects(t.Context(), fw, fw, q, q); !errors.Is(err, policy.ErrNotEquivalent) {
		t.Fatal("equal projected set supplied no strict policy preimage", err)
	}
	// A homogeneous policy effect is provable for every original input even
	// when the native policy view differs from the wire destination view.
	data.Rules[1].LogStart = fm.Irrelevant
	fw = migrationGraph(t, data)
	if _, err := (policy.Engine{}).EquivalentPacketEffects(t.Context(), fw, fw, q, q); err != nil {
		t.Fatal("homogeneous native policy effect lost its wire domain", err)
	}
}

func TestPacketEquivalencePreservesPolicyEffectPartitions(t *testing.T) {
	q := migrationRequest(t)
	left, right := migrationData("paloalto"), migrationData("hillstone")
	for _, d := range []*fm.Data{&left, &right} {
		d.Addresses = []fm.AddressRecord{{Object: fm.Object{ID: "first-source"}, Ranges: []flow.AddressRange{rangeOf("192.0.2.0/32")}}}
		first := d.Rules[0]
		first.ID, first.Position, first.LogStart = "first", 1, fm.Known
		first.Match.AnySource = false
		first.Match.Sources = []fm.AddressRef{{Kind: fm.AddressObject, ID: "first-source"}}
		second := d.Rules[0]
		second.ID, second.Position = "remaining", 2
		d.Rules = []fm.RuleRecord{first, second}
	}
	source, target := migrationGraph(t, left), migrationGraph(t, right)
	if proof, err := (policy.Engine{}).EquivalentPacketEffects(t.Context(), source, target, q, q); err != nil || proof.Partitions != 2 {
		t.Fatal("original policy partition was not preserved", proof, err)
	}
	right.Rules[0].LogStart, right.Rules[1].LogStart = fm.Irrelevant, fm.Known
	if _, err := (policy.Engine{}).EquivalentPacketEffects(t.Context(), source, migrationGraph(t, right), q, q); !errors.Is(err, policy.ErrNotEquivalent) {
		t.Fatal("same action and logging set hid swapped traffic ownership", err)
	}
	if _, err := (policy.Engine{Limits: policy.Limits{MaxCombinations: 1}}).EquivalentPacketEffects(t.Context(), source, target, q, q); !errors.Is(err, policy.ErrBudget) {
		t.Fatal("effect partition count escaped its cap", err)
	}
}

func TestPacketEquivalenceNormalizesEffectivePoolPortDefaults(t *testing.T) {
	q := migrationRequest(t)
	for _, mode := range []fm.TranslationMode{fm.DynamicIP, fm.DynamicIPPort} {
		a, b := dynamicMigrationData("paloalto"), dynamicMigrationData("hillstone")
		a.DynamicNATs[0].SourceMode, b.DynamicNATs[0].SourceMode = mode, mode
		b.NATPools[0].Ports = flow.Interval{High: 65535}
		if _, err := (policy.Engine{}).EquivalentPacketEffects(t.Context(), migrationGraph(t, a), migrationGraph(t, b), q, q); err != nil {
			t.Fatal("default and explicit native port domains differ", mode, err)
		}
		if mode == fm.DynamicIPPort {
			b.NATPools[0].Ports.Low = 1024
			if _, err := (policy.Engine{}).EquivalentPacketEffects(t.Context(), migrationGraph(t, a), migrationGraph(t, b), q, q); !errors.Is(err, policy.ErrNotEquivalent) {
				t.Fatal("reserved allocation ports were erased", err)
			}
		}
	}
}

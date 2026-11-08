package operations

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
)

func inputRange(first, last string) flow.AddressRange {
	return flow.AddressRange{First: netip.MustParseAddr(first), Last: netip.MustParseAddr(last)}
}

func TestInputNormalizesBusinessSets(t *testing.T) {
	a := AccessRequest{
		Src:     "\ufeff \"１９２．０．２．１２９　／　２５\"； '192.0.2.129/25'; 2001:db8::2 - 2001:db8::3",
		Dst:     "２０３．０．１１３．１、\"203.0.113.1\";2001:db8:1::1",
		Service: "\"４４３\", tcp / 443; ' UDP　/　５３－５４ '; udp/54-55",
	}
	got, normalized, err := normalizeInput(t.Context(), a, 32)
	if err != nil {
		t.Fatal(err)
	}
	wantSrc := []flow.AddressRange{
		inputRange("192.0.2.128", "192.0.2.255"), inputRange("2001:db8::2", "2001:db8::3"),
	}
	wantDst := []flow.AddressRange{
		inputRange("203.0.113.1", "203.0.113.1"), inputRange("2001:db8:1::1", "2001:db8:1::1"),
	}
	if !slices.Equal(normalized.Sources, wantSrc) || !slices.Equal(normalized.Destinations, wantDst) {
		t.Fatal("address cleanup changed the requested set", normalized)
	}
	if normalized.AllServices || !normalized.ServiceSpecified || len(normalized.Services) != 2 || got.Traffic.RegionCount() != 4 {
		t.Fatal("duplicates or family pairing changed the product", normalized, got.Traffic)
	}
	for i, want := range []struct {
		protocol uint16
		ports    flow.Interval
	}{{6, flow.Interval{Low: 443, High: 443}}, {17, flow.Interval{Low: 53, High: 55}}} {
		term := normalized.Services[i]
		if term.Protocol != (flow.Interval{Low: want.protocol, High: want.protocol}) || term.DestinationPort != want.ports {
			t.Fatal("service normalization changed protocol or ports", term, want)
		}
	}
	if got.Src != a.Src || got.Dst != a.Dst || got.Service != a.Service || !a.Traffic.Empty() {
		t.Fatal("normalization overwrote original business input", got, a)
	}
}

func TestInputBuildsCartesianProductWithinOneRequest(t *testing.T) {
	a, normalized, err := normalizeInput(t.Context(), AccessRequest{
		Src: "\"192.0.2.1, 192.0.2.3\"", Dst: "198.51.100.2 198.51.100.4", Service: "443 udp/53",
	}, 16)
	if err != nil || a.Traffic.RegionCount() != 8 || normalized == nil {
		t.Fatal(a, normalized, err)
	}
	for _, src := range []string{"192.0.2.1", "192.0.2.3"} {
		for _, dst := range []string{"198.51.100.2", "198.51.100.4"} {
			for _, service := range []struct{ protocol, port uint16 }{{6, 443}, {17, 53}} {
				found := false
				for _, region := range a.Traffic.Regions() {
					found = found || region.Source == inputRange(src, src) && region.Destination == inputRange(dst, dst) &&
						region.Protocol == (flow.Interval{Low: service.protocol, High: service.protocol}) &&
						region.DestinationPort == (flow.Interval{Low: service.port, High: service.port})
				}
				if !found {
					t.Fatal("source and destination lists were zipped", src, dst, service)
				}
			}
		}
	}
}

func TestInputOmittedServiceIsAnUnrestrictedQueryFilter(t *testing.T) {
	for _, service := range []string{"", "\ufeff \t", "any", "\" ＡＮＹ \"", "\" \t \""} {
		t.Run(service, func(t *testing.T) {
			a, normalized, err := normalizeInput(t.Context(), AccessRequest{
				Src: "192.0.2.1", Dst: "198.51.100.1", Service: service,
			}, 8)
			if err != nil || normalized == nil || !normalized.AllServices || a.Traffic.RegionCount() != 1 {
				t.Fatal(a, normalized, err)
			}
			specified := service == "any" || service == "\" ＡＮＹ \""
			if normalized.ServiceSpecified != specified {
				t.Fatal("query omission and explicit any were conflated", service, normalized)
			}
			r := a.Traffic.Regions()[0]
			if r.Protocol != (flow.Interval{High: 255}) || r.DestinationPort != (flow.Interval{High: 65535}) {
				t.Fatal("omitted service defaulted to one protocol or port", r)
			}
		})
	}
	_, n, err := normalizeInput(t.Context(), AccessRequest{Src: "192.0.2.1", Dst: "198.51.100.1", Service: "0-65535"}, 8)
	if err != nil || n.AllServices || n.Services[0].Protocol != (flow.Interval{Low: 6, High: 6}) {
		t.Fatal("bare port range did not retain tcp semantics", n, err)
	}
}

func TestInputRejectsInvalidValuesWithoutPartialTraffic(t *testing.T) {
	for _, tc := range []struct {
		name, field, raw, value string
	}{
		{"invalid ipv4", "src", "192.0.2.1;192.0.2.999", "192.0.2.999"},
		{"full width invalid token", "src", "192.0.2.1;１９２．０．２．９９９", "１９２．０．２．９９９"},
		{"leading zero", "src", "192.0.2.1 192.00.2.2", "192.00.2.2"},
		{"invalid ipv6", "dst", "2001:db8::gg", "2001:db8::gg"},
		{"ipv4 mask", "src", "192.0.2.1 / 33", "192.0.2.1 / 33"},
		{"ipv6 mask", "dst", "2001:db8::1/129", "2001:db8::1/129"},
		{"negative mask", "src", "192.0.2.1/-1", "192.0.2.1/-1"},
		{"dotted mask", "src", "192.0.2.1/255.255.255.0", "192.0.2.1/255.255.255.0"},
		{"reversed ipv4 range", "src", "192.0.2.2 - 192.0.2.1", "192.0.2.2 - 192.0.2.1"},
		{"reversed ipv6 range", "dst", "2001:db8::2-2001:db8::1", "2001:db8::2-2001:db8::1"},
		{"mixed range", "src", "192.0.2.1-2001:db8::1", "192.0.2.1-2001:db8::1"},
		{"scoped ipv6", "src", "fe80::1%eth0", "fe80::1%eth0"},
		{"scoped prefix", "src", "fe80::1%eth0/64", "fe80::1%eth0/64"},
		{"scoped range", "src", "fe80::1%eth0-fe80::2%eth0", "fe80::1%eth0-fe80::2%eth0"},
		{"unterminated quote", "src", "\"192.0.2.1", "\"192.0.2.1"},
		{"invalid tcp port", "service", "443;tcp/65536", "tcp/65536"},
		{"invalid udp port", "service", "443;udp/-1", "udp/-1"},
		{"reversed port range", "service", "tcp/443-80", "tcp/443-80"},
		{"signed port", "service", "+443", "+443"},
		{"nondecimal port", "service", "0x50", "0x50"},
		{"unknown protocol", "service", "icmp/8", "icmp/8"},
		{"mixed wildcard", "service", "443;any", "any"},
		{"empty separated service", "service", ";,", ";,"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := AccessRequest{Src: "192.0.2.1", Dst: "198.51.100.1", Service: "443"}
			switch tc.field {
			case "src":
				a.Src = tc.raw
			case "dst":
				a.Dst = tc.raw
			case "service":
				a.Service = tc.raw
			}
			got, normalized, err := normalizeInput(t.Context(), a, 32)
			var invalid *InputError
			if !errors.Is(err, ErrInvalid) || !errors.As(err, &invalid) {
				t.Fatal("invalid value was accepted", got, normalized, err)
			}
			if invalid.Field != tc.field || invalid.Value != tc.value {
				t.Fatal("error lost the original invalid value", invalid, tc)
			}
			if normalized != nil || !got.Traffic.Empty() || !reflect.DeepEqual(got, a) {
				t.Fatal("invalid row retained partial traffic", got, normalized)
			}
		})
	}
}

func TestInputRejectsUnmatchedAddressFamilies(t *testing.T) {
	for _, a := range []AccessRequest{
		{Src: "192.0.2.1;2001:db8::1", Dst: "198.51.100.1"},
		{Src: "192.0.2.1", Dst: "198.51.100.1;2001:db8:1::1"},
		{Src: "2001:db8::1", Dst: "198.51.100.1"},
	} {
		got, normalized, err := normalizeInput(t.Context(), a, 16)
		if !errors.Is(err, ErrInvalid) || normalized != nil || !got.Traffic.Empty() {
			t.Fatal("an address family was silently dropped", got, normalized, err)
		}
	}
}

func TestInputFormsAreExclusive(t *testing.T) {
	typed, err := flow.AllTraffic(8)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []AccessRequest{
		{},
		{Service: "443"},
		{Src: "192.0.2.1"},
		{Src: "192.0.2.1", Dst: "198.51.100.1", Traffic: typed},
		{Src: "192.0.2.1", Dst: "198.51.100.1", Native: &NativeEffects{}},
		{Src: "192.0.2.1", Dst: "198.51.100.1", View: inventory.Real},
		{Src: "192.0.2.1", Dst: "198.51.100.1", View: inventory.Translated},
		{Src: "192.0.2.1", Dst: "198.51.100.1", WireCandidates: []WireCandidate{{Traffic: typed}}},
	} {
		_, normalized, err := normalizeInput(t.Context(), a, 16)
		if !errors.Is(err, ErrInvalid) || normalized != nil {
			t.Fatal("ambiguous or missing business input was accepted", a, normalized, err)
		}
	}
	advanced := AccessRequest{Traffic: typed, Native: &NativeEffects{}, Targets: []AccessTarget{{Device: "fw"}}}
	got, normalized, err := normalizeInput(t.Context(), advanced, 16)
	if err != nil || normalized != nil || !reflect.DeepEqual(got, advanced) {
		t.Fatal("advanced input changed during text normalization", got, normalized, err)
	}
	simple := AccessRequest{Src: "192.0.2.1", Dst: "198.51.100.1", Targets: []AccessTarget{{Device: "fw"}}}
	got, normalized, err = normalizeInput(t.Context(), simple, 16)
	if err != nil || normalized == nil || !reflect.DeepEqual(got.Targets, simple.Targets) {
		t.Fatal("explicit target rejected for simple traffic", got, normalized, err)
	}
}

func TestInputBoundsExpansionAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		a     AccessRequest
		limit int
	}{
		{AccessRequest{Src: "192.0.2.1,192.0.2.3", Dst: "198.51.100.1"}, 1},
		{AccessRequest{Src: "192.0.2.1", Dst: "198.51.100.1", Service: "443,udp/53"}, 1},
		{AccessRequest{Src: "192.0.2.1,192.0.2.3", Dst: "198.51.100.1,198.51.100.3", Service: "443,udp/53"}, 4},
		{AccessRequest{Src: "192.0.2.1", Dst: "198.51.100.1"}, 0},
	} {
		got, normalized, err := normalizeInput(t.Context(), tc.a, tc.limit)
		if !errors.Is(err, policy.ErrBudget) || normalized != nil || !got.Traffic.Empty() {
			t.Fatal("budget returned partial input", got, normalized, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, a := range []AccessRequest{{}, {Src: "192.0.2.1", Dst: "198.51.100.1"}} {
		_, normalized, err := normalizeInput(ctx, a, 0)
		if !errors.Is(err, context.Canceled) || normalized != nil {
			t.Fatal("cancellation did not precede validation and allocation", normalized, err)
		}
	}
}

func TestInputBatchRetainsValidSiblingsAndAllServiceMatches(t *testing.T) {
	store, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fw, err := fm.Seal(fm.Data{
		Metadata: fm.Metadata{Device: "input-test", Vendor: "hillstone"},
		Zones:    []fm.ZoneRecord{{Object: fm.Object{ID: "inside"}}, {Object: fm.Object{ID: "outside"}}},
		Services: []fm.ServiceRecord{
			{Object: fm.Object{ID: "https"}, Terms: []fm.ServiceTerm{{Protocol: flow.Interval{Low: 6, High: 6},
				SourcePort: flow.Interval{High: 65535}, DestinationPort: flow.Interval{Low: 443, High: 443},
				ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}}}},
			{Object: fm.Object{ID: "dns"}, Terms: []fm.ServiceTerm{{Protocol: flow.Interval{Low: 17, High: 17},
				SourcePort: flow.Interval{High: 65535}, DestinationPort: flow.Interval{Low: 53, High: 53},
				ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}}}},
		},
		Rules: []fm.RuleRecord{
			{Object: fm.Object{ID: "allow-https"}, RuleSet: "security", Action: fm.Permit,
				Match: fm.Match{AnySource: true, AnyDestination: true, AnyFromZone: true, AnyToZone: true,
					Services: []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "https"}}}},
			{Object: fm.Object{ID: "deny-dns"}, RuleSet: "security", Position: 1, Action: fm.Deny,
				Match: fm.Match{AnySource: true, AnyDestination: true, AnyFromZone: true, AnyToZone: true,
					Services: []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "dns"}}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Publish(t.Context(), fw, snapshot.PublishOptions{PublicationID: "input-test"}); err != nil {
		t.Fatal(err)
	}
	searcher, err := NewSearcher(SearcherOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	targets := []AccessTarget{{Device: "input-test", Request: policy.Request{FromZone: "inside", ToZone: "outside"}}}
	result, err := searcher.Query(t.Context(), BatchRequest{Version: 1, Requests: []AccessRequest{
		{Src: "192.0.2.1,invalid", Dst: "198.51.100.1", Service: "443", Targets: targets},
		{Src: "192.0.2.1", Dst: "198.51.100.1", Targets: targets},
		{Src: "192.0.2.3", Dst: "198.51.100.3", Service: "udp/53", Targets: targets},
	}})
	if err != nil || len(result.Inputs) != 3 {
		t.Fatal(result, err)
	}
	bad := result.Inputs[0]
	if bad.Error == nil || bad.Error.Value != "invalid" || bad.Normalized != nil || len(bad.Outcomes) != 0 || !bad.Request.Traffic.Empty() {
		t.Fatal("bad application row was partially queried", bad)
	}
	all := result.Inputs[1]
	if all.Error != nil || all.Normalized == nil || !all.Normalized.AllServices || len(all.Outcomes) != 1 {
		t.Fatal("valid sibling was discarded", all, result.Issues)
	}
	p := all.Outcomes[0].Policy
	if !p.Complete || p.Allowed.Empty() || p.Denied.Empty() || p.Unmatched.Empty() || len(p.Decisions) != 2 {
		t.Fatal("omitted service did not query both tcp and udp policies", p)
	}
	udp := result.Inputs[2]
	if udp.Error != nil || len(udp.Outcomes) != 1 || udp.Outcomes[0].Policy.Denied.Empty() {
		t.Fatal("later valid row was not queried", udp)
	}

	_, err = searcher.Query(t.Context(), BatchRequest{Version: 1, Requests: []AccessRequest{{
		Src: strings.Repeat(" ", MaxRequestBytes+1), Dst: "198.51.100.1",
	}}})
	if !errors.Is(err, policy.ErrBudget) {
		t.Fatal("direct API bypassed request byte budget", err)
	}
}

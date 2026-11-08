package policy_test

import (
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestStaticAliasesProveAddressAndPortOffsets(t *testing.T) {
	d := preimageData("paloalto")
	d.StaticNATs[0].DestinationPorts = []fm.PortMapping{{Original: flow.Interval{Low: 443, High: 446}, Translated: flow.Interval{Low: 8443, High: 8446}, Mode: fm.Offset}}
	fw := migrationGraph(t, d)
	q := migrationRequest(t)
	b := preimagePacket("192.0.2.1", "198.51.100.30", 8442)
	b.DestinationPort.High = 8445
	q.Traffic = preimageTraffic(t, b)
	result, err := (policy.Engine{}).DiscoverStaticAliases(t.Context(), fw, q, policy.RealView)
	if err != nil || len(result.Candidates) != 1 || !result.Unknown.Empty() || !result.Ambiguous.Empty() {
		t.Fatal(result, err)
	}
	b.DestinationPort.Low = 8443
	assertPreimage(t, result.Candidates[0].Business, preimageTraffic(t, b), nil)
	b.Destination = rangeOf("198.51.100.10/32")
	b.DestinationPort = flow.Interval{Low: 443, High: 445}
	assertPreimage(t, result.Candidates[0].Wire, preimageTraffic(t, b), nil)
	assertPreimage(t, result.Unmatched, preimageTraffic(t, preimagePacket("192.0.2.1", "198.51.100.30", 8442)), nil)
}

func TestStaticAliasesRetainPortStageAndNativeShadowing(t *testing.T) {
	for _, test := range []string{"singleton-constant", "port-only", "source-port", "earlier-rule", "many-to-one"} {
		t.Run(test, func(t *testing.T) {
			d := preimageData("paloalto")
			view := policy.RealView
			business := preimagePacket("192.0.2.1", "198.51.100.30", 8443)
			wire := preimagePacket("192.0.2.1", "198.51.100.10", 443)
			switch test {
			case "singleton-constant":
				d.StaticNATs[0].DestinationPorts[0].Mode = fm.Constant
			case "port-only":
				d.StaticNATs[0].Destination = nil
				wire.Destination = business.Destination
			case "source-port":
				d.StaticNATs[0].SourcePorts = []fm.PortMapping{{Original: flow.Interval{Low: 1000, High: 1000}, Translated: flow.Interval{Low: 1024, High: 1024}, Mode: fm.Offset}}
				view = policy.TranslatedView
				wire.SourcePort = flow.Interval{Low: 1000, High: 1000}
			case "earlier-rule":
				earlier := d.StaticNATs[0]
				earlier.ID, earlier.Order.Position = "earlier", 0
				earlier.DestinationPorts = []fm.PortMapping{{Original: flow.Interval{Low: 443, High: 443}, Translated: flow.Interval{Low: 9443, High: 9443}, Mode: fm.Offset}}
				d.StaticNATs[0].Order.Position = 1
				d.StaticNATs = append([]fm.StaticNATRecord{earlier}, d.StaticNATs...)
			case "many-to-one":
				d.StaticNATs[0].DestinationPorts = []fm.PortMapping{{Original: flow.Interval{Low: 443, High: 446}, Translated: flow.Interval{Low: 8443, High: 8443}, Mode: fm.Constant}}
			}
			q := migrationRequest(t)
			q.Traffic = preimageTraffic(t, business)
			result, err := (policy.Engine{}).DiscoverStaticAliases(t.Context(), migrationGraph(t, d), q, view)
			if err != nil {
				t.Fatal(err)
			}
			switch test {
			case "earlier-rule":
				if len(result.Candidates) != 0 || !result.Unknown.Empty() {
					t.Fatal("shadowed catalog port relation became a wire alias", result)
				}
				assertPreimage(t, result.Unmatched, q.Traffic, nil)
			case "many-to-one":
				if len(result.Candidates) != 0 {
					t.Fatal("ambiguous original service was selected", result)
				}
				assertPreimage(t, result.Unknown, q.Traffic, nil)
			default:
				if len(result.Candidates) != 1 || !result.Unknown.Empty() || !result.Ambiguous.Empty() || !result.Unmatched.Empty() {
					t.Fatal(result)
				}
				assertPreimage(t, result.Candidates[0].Wire, preimageTraffic(t, wire), nil)
			}
		})
	}
}

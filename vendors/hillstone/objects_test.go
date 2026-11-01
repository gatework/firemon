package hillstone_test

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/hillstone"
)

func TestReopenedAddressDefinitionsRetainOneIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, declarations string
		group              bool
	}{
		{"literal members", "address a\nip 192.0.2.10/32\nexit\naddress a\nip 192.0.2.20/32\nexit\n", false},
		{"mixed group members", "address a\nip 192.0.2.10/32\nexit\naddress a\nmember b\nexit\naddress b\nip 192.0.2.20/32\nexit\n", true},
		{"later empty group", "address b\nip 192.0.2.10/32\nip 192.0.2.20/32\nexit\naddress a\nmember b\nexit\naddress a\nexit\n", true},
		{"forward group", "address a\nmember b\nexit\naddress b\nmember c\nexit\naddress b\nexit\naddress c\nip 192.0.2.10/32\nip 192.0.2.20/32\nexit\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw := parse(t, tc.declarations+"policy-global\nrule id 1\nsrc-addr a\ndst-addr any\nservice any\naction permit\nexit\nexit\n")
			if !fw.Complete() {
				t.Fatal(fw.Diagnostics())
			}
			r := fw.Rule("1")
			if tc.group && (len(r.SourceGroups()) != 1 || r.SourceGroups()[0] != fw.AddressGroup("a")) {
				t.Fatal("rule lost named group identity")
			}
			set, known, err := (policy.Engine{}).ResolveAddresses(t.Context(), fw, r.Record().Match.Sources, false)
			if err != nil || !known {
				t.Fatalf("resolve: known=%v, err=%v", known, err)
			}
			var got []string
			for _, r := range set.Ranges() {
				got = append(got, r.First.String()+"-"+r.Last.String())
			}
			want := []string{"192.0.2.10-192.0.2.10", "192.0.2.20-192.0.2.20"}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("address members: got %v, want %v", got, want)
			}
		})
	}
}

func TestReopenedServiceAndGroupRetainMembers(t *testing.T) {
	fw := parse(t, "servgroup apps\nservice web\nexit\nservgroup apps\nservice dns\nexit\nservice web\ntcp dst-port 80\nexit\nservice web\ntcp dst-port 443\nexit\nservice dns\nudp dst-port 53\nexit\n")
	if !fw.Complete() || len(fw.Services()) != 2 || len(fw.ServiceGroups()) != 1 {
		t.Fatal("reopened service identities", fw.Diagnostics())
	}
	terms, known, err := (policy.Engine{}).ResolveServices(t.Context(), fw, []fm.ServiceRef{{Kind: fm.ServiceGroupObject, ID: "apps"}}, false)
	if err != nil || !known {
		t.Fatalf("resolve: known=%v, err=%v", known, err)
	}
	got := make(map[string]bool)
	for _, term := range terms {
		got[fmt.Sprintf("%d:%d-%d", term.Protocol.Low, term.DestinationPort.Low, term.DestinationPort.High)] = true
	}
	if !reflect.DeepEqual(got, map[string]bool{"6:80-80": true, "6:443-443": true, "17:53-53": true}) {
		t.Fatal("service members lost or widened", got)
	}
}

func TestNamedServiceTakesPrecedenceOverSameNameGroup(t *testing.T) {
	// Perl getServiceOrServiceGroupFromSrvGroupMemberName checks a declared
	// service before a group. Declaration order must not change the binding.
	service := "service shared\ntcp dst-port 443\nexit\n"
	group := "servgroup shared\nservice dns\nexit\n"
	for _, tc := range []struct{ name, declarations string }{
		{"service first", service + group},
		{"group first", group + service},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw := parse(t, "service dns\nudp dst-port 53\nexit\n"+tc.declarations+"servgroup apps\nservice shared\nexit\n")
			if !fw.Complete() {
				t.Fatal(fw.Diagnostics())
			}
			apps := fw.ServiceGroup("apps")
			if got := apps.Services(); len(got) != 1 || got[0] != fw.Service("shared") || len(apps.Groups()) != 0 {
				t.Fatal("same-name group shadowed the declared service")
			}
		})
	}
}

func TestReopenedObjectRetainsUnsupportedSource(t *testing.T) {
	text := "address a\nip 192.0.2.10/32\nunsupported option\nexit\naddress a\nip 192.0.2.20/32\nexit\n"
	fw := parse(t, text)
	if fw.Complete() || len(fw.Address("a").Record().Unsupported) == 0 {
		t.Fatal("reopening erased unsupported member")
	}
	if fw.Export().Evidence[2].State != fm.Pending {
		t.Fatal("unknown source was claimed")
	}
	_, known, err := (policy.Engine{}).ResolveAddresses(t.Context(), fw, []fm.AddressRef{{Kind: fm.AddressObject, ID: "a"}}, false)
	if err != nil || known {
		t.Fatalf("unsupported object became known: %v, %v", known, err)
	}
	if fw.Raw() != text {
		t.Fatal("source was rewritten")
	}
}

func TestDifferentScopesDoNotMergeNamedObjects(t *testing.T) {
	text := "ip vrouter blue\naddress a\nip 192.0.2.10/32\nexit\nexit\nip vrouter red\naddress a\nip 192.0.2.20/32\nexit\nexit\n"
	fw, err := hillstone.Parse(context.Background(), config.Source{Text: text, Complete: true}, fm.Metadata{Device: "synthetic"})
	if err == nil && fw.Complete() {
		t.Fatal("same name in separate scopes silently merged")
	}
}

func TestReopenedDeclarationsPreserveFirstSeenOrder(t *testing.T) {
	fw := parse(t, "address b\nip 192.0.2.2/32\nexit\naddress a\nip 192.0.2.1/32\nexit\naddress b\nip 192.0.2.3/32\nexit\n")
	if got := fw.Addresses(); len(got) != 2 || got[0].ID() != "b" || got[1].ID() != "a" {
		t.Fatal("object iteration lost declaration order")
	}
	var spans []int
	for _, span := range fw.Address("b").Record().Spans {
		spans = append(spans, span.First)
	}
	if !reflect.DeepEqual(spans, []int{1, 2, 7, 8}) {
		t.Fatal("accepted declaration/member spans missing or out of order", spans)
	}
	for _, e := range fw.Export().Evidence {
		if e.State == fm.Pending {
			t.Fatal("accepted reopening left pending source", e)
		}
	}
}

func TestIncompleteReopenedObjectRetainsDiagnostic(t *testing.T) {
	fw := parse(t, strings.TrimSuffix("address a\nip 192.0.2.10/32\nexit\naddress a\nip 192.0.2.20/32\nexit\n", "exit\n"))
	if fw.Complete() {
		t.Fatal("truncated reopening became complete")
	}
}

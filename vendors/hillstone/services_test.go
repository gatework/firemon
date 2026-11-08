package hillstone_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors/hillstone"
)

func TestObservedServiceBookKeepsICMPAndExplicitPrecedence(t *testing.T) {
	const book = `{"predefined_services":{"PING":[{"protocol":"icmp","source_port":"0","destination_port":"8"}],"web":[{"protocol":"tcp","destination_port":"80"}]}}`
	services, err := hillstone.ReadServices(t.Context(), strings.NewReader(book), 10)
	if err != nil {
		t.Fatal(err)
	}
	fw, err := (hillstone.Parser{Services: services}).Parse(t.Context(), config.Source{Text: "service web\ntcp dst-port 443\nexit\nservgroup apps\nservice PING\nservice web\nexit\n", Complete: true}, fm.Metadata{Device: "synthetic"})
	if err != nil || !fw.Complete() {
		t.Fatal(err)
	}
	services[0].Terms[0].ICMPType.High = 255
	var encoded bytes.Buffer
	if err := snapshot.Encode(&encoded, fw); err != nil {
		t.Fatal(err)
	}
	restored, err := snapshot.Decode(&encoded, snapshot.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, graph := range []*fm.Firewall{fw, restored} {
		terms, known, err := (policy.Engine{}).ResolveServices(t.Context(), graph, []fm.ServiceRef{{Kind: fm.ServiceGroupObject, ID: "apps"}}, false)
		if err != nil || !known || len(terms) != 2 {
			t.Fatal("book reference lost", err)
		}
		for _, term := range terms {
			if term.Protocol.Low == 1 && (term.ICMPType.Low != 8 || term.ICMPType.High != 8 || term.ICMPCode.High != 0) {
				t.Fatal("PING widened to ICMP", term)
			}
			if term.Protocol.Low == 6 && (term.DestinationPort.Low != 443 || term.DestinationPort.High != 443) {
				t.Fatal("catalog overrode explicit service", term)
			}
		}
	}
}

func TestServiceBookRejectsInvalidOrUnboundedTerms(t *testing.T) {
	for _, input := range []string{
		`{"predefined_services":{"bad~":[{"protocol":"tcp"}]}}`,
		`{"predefined_services":{"bad":[{"protocol":"300"}]}}`,
		`{"predefined_services":{"bad":[{"protocol":"icmp","destination_port":"256"}]}}`,
		`{"predefined_services":{"bad":[{"protocol":"tcp","destination_port":"443-80"}]}}`,
		`{"predefined_services":{"bad":[{"protocol":"any","destination_port":"443"}]}}`,
		`{"predefined_services":{"bad":[{"protocol":"47","source_port":"80"}]}}`,
		`{"predefined_services":{"bad":[{"protocol":"tcp"},{"protocol":"udp"}]}}`,
	} {
		if _, err := hillstone.ReadServices(t.Context(), strings.NewReader(input), 1); !errors.Is(err, config.ErrSource) {
			t.Fatal("invalid book accepted", err)
		}
	}
}

func TestParserKeepsCatalogAndTopologyLocalToEachParse(t *testing.T) {
	const book = `{"predefined_services":{"web":[{"protocol":"tcp","destination_port":"80"}]}}`
	services, err := hillstone.ReadServices(t.Context(), strings.NewReader(book), 10)
	if err != nil {
		t.Fatal(err)
	}
	p := hillstone.Parser{Services: services}
	const rule = "rule id 1\nsrc-zone inside\ndst-zone any\nsrc-addr clients\ndst-addr any\nservice web\naction permit\nexit\n"
	for _, tt := range []struct {
		name, text, scope string
		kind              fm.Kind
		port              uint16
	}{
		{
			name: "declared group and service",
			text: "zone inside\nvrouter blue\nexit\ninterface ge0\nzone inside\nexit\n" +
				"address clients\nmember host\nexit\naddress host\nip 192.0.2.1\nexit\n" +
				"service web\ntcp dst-port 443\nexit\n",
			scope: "blue", kind: fm.AddressGroupObject, port: 443,
		},
		{
			name: "address and book service",
			text: "zone inside\nexit\ninterface ge0\nzone inside\nexit\n" +
				"address clients\nip 192.0.2.2\nexit\n",
			kind: fm.AddressObject, port: 80,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			graph, err := p.Parse(t.Context(), config.Source{Text: tt.text + rule, Complete: true}, fm.Metadata{Device: "synthetic"})
			if err != nil {
				t.Fatal(err)
			}
			r := graph.Rule("1").Record()
			if r.Scope != tt.scope || graph.Interface("ge0").Scope() != tt.scope || r.Match.Sources[0].Kind != tt.kind {
				t.Fatal("catalog or topology leaked between parses")
			}
			terms, known, err := (policy.Engine{}).ResolveServices(t.Context(), graph, r.Match.Services, false)
			if err != nil || !known || len(terms) != 1 || terms[0].DestinationPort.Low != tt.port || terms[0].DestinationPort.High != tt.port {
				t.Fatal("service precedence leaked between parses", terms, err)
			}
		})
	}
}

package config_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func TestXMLScannerRetainsNativeHierarchyAndUnclaimedByteEvidence(t *testing.T) {
	raw := "<config>\r\n<address><entry name=\"quoted &amp; name\"><ip-netmask>192.0.2.1/32</ip-netmask></entry></address><empty/></config>"
	d, err := config.XML(context.Background(), config.Source{Text: raw, Complete: true}, config.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if d.Root.Name.Local != "config" || d.Root.Children[0].Children[0].Attributes[0].Value != "quoted & name" || len(d.Root.Children) != 2 {
		t.Fatal("native hierarchy lost")
	}
	n := d.Root.Children[0].Children[0].Children[0]
	if raw[n.Span.StartByte:n.Span.EndByte] != "<ip-netmask>192.0.2.1/32</ip-netmask>" || n.Text != "192.0.2.1/32" || n.Span.First != 2 {
		t.Fatal("wrong byte/line evidence", n)
	}
	for _, e := range d.Content.Evidence() {
		if e.State != 0 {
			t.Fatal("structure claimed semantic evidence")
		}
	}
}
func TestXMLScannerRejectsEntitiesMixedContentAndResourceExcess(t *testing.T) {
	for _, raw := range []string{
		"<!DOCTYPE config [<!ENTITY external SYSTEM 'file:///private'>]><config>&external;</config>",
		"<config/><config/>", "<config>unscoped<address/></config>", "<config><address></config>",
		strings.Repeat("<x>", 66) + strings.Repeat("</x>", 66),
	} {
		if _, err := config.XML(context.Background(), config.Source{Text: raw}, config.Limits{}); err == nil {
			t.Fatal("invalid XML accepted", raw[:min(80, len(raw))])
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := config.XML(ctx, config.Source{Text: "<config/>"}, config.Limits{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestXMLClaimsDoNotConsumeUnknownSiblingOnSameLine(t *testing.T) {
	raw := "<config><known>192.0.2.1</known><unknown>condition</unknown></config>"
	d, err := config.XML(t.Context(), config.Source{Text: raw}, config.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if lines := d.Content.Lines(); len(lines) != 1 || lines[0].Raw != raw {
		t.Fatal("XML source is not indexed by physical lines", lines)
	}
	b, err := config.NewBuilder(d.Content, fm.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	known, unknown := d.Root.Children[0], d.Root.Children[1]
	tx := b.Begin()
	tx.Parse(known.Claims...)
	tx.Emit(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "known"}}}})
	if err := b.Commit(tx); err != nil {
		t.Fatal(err)
	}
	evidence := d.Content.Evidence()
	for _, claim := range known.Claims {
		if evidence[claim-1].State != fm.Parsed {
			t.Fatal("known node was not committed")
		}
	}
	for _, claim := range unknown.Claims {
		if e := evidence[claim-1]; e.State != fm.Pending || e.Span.First != 1 || e.Span.Last != 1 {
			t.Fatal("unknown sibling lost evidence", e)
		}
	}
	failed := b.Begin()
	failed.Parse(unknown.Claims...)
	failed.Parse(known.Claims...)
	if err := b.Commit(failed); err == nil {
		t.Fatal("repeated claim accepted")
	}
	for _, claim := range unknown.Claims {
		if d.Content.Evidence()[claim-1].State != fm.Pending {
			t.Fatal("failed transaction consumed unknown sibling")
		}
	}
}

func TestXMLBoundsPhysicalLinesAndTokens(t *testing.T) {
	raw := "<config>\n\n\n</config>"
	if _, err := config.XML(t.Context(), config.Source{Text: raw}, config.Limits{MaxLines: 3}); !errors.Is(err, config.ErrSource) {
		t.Fatal("excess physical line accepted", err)
	}
	d, err := config.XML(t.Context(), config.Source{Text: raw}, config.Limits{MaxLines: 4})
	if err != nil || len(d.Content.Lines()) != 4 || len(d.Content.Evidence()) != 3 {
		t.Fatal("physical lines and tokens were conflated", err)
	}
	raw = "<config><known/><unknown/></config>"
	if _, err := config.XML(t.Context(), config.Source{Text: raw}, config.Limits{MaxLines: 3}); !errors.Is(err, config.ErrSource) {
		t.Fatal("excess XML token accepted", err)
	}
}

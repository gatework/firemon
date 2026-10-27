package config_test

import (
	"context"
	"errors"
	"github.com/gatework/firemon/config"
	"strings"
	"testing"
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
	for _, e := range d.Cursor.Evidence() {
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

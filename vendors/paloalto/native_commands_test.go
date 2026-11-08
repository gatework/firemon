package paloalto_test

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors/paloalto"
)

func TestNativeNATCommandsPreserveLiteralAddresses(t *testing.T) {
	for _, tt := range []struct {
		name, source, destination, translation string
	}{
		{"source prefix", "192.0.2.10/32", "any", "source-translation static-ip translated-address 198.51.100.10"},
		{"destination host", "any", "203.0.113.20", "destination-translation translated-address 192.0.2.20"},
		{"source and destination ranges", "192.0.2.10-192.0.2.13", "203.0.113.20-203.0.113.23", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before, after := literalNATCaptures(t, tt.source, tt.destination, tt.translation)
			commands, err := (paloalto.Renderer{}).RenderNative(t.Context(), before, after, literalNATChanges(after))
			if err != nil {
				t.Fatal("parsed literal NAT could not be rendered", err)
			}
			for _, side := range []struct{ field, value string }{{"source", tt.source}, {"destination", tt.destination}} {
				value := side.value
				if value != "any" {
					value = `"` + value + `"`
				}
				want := `set rulebase nat rules "literal" ` + side.field + " " + value
				if !slices.Contains(commands, want) {
					t.Fatalf("literal selector changed: missing %q in %v", want, commands)
				}
			}
			for _, command := range commands {
				if strings.HasPrefix(command, "set address ") {
					t.Fatal("inline NAT address became a named declaration", command)
				}
			}
		})
	}
}

func TestNativeNATCommandsRejectInvalidLiteralAddresses(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*fm.Data)
		want   error
	}{
		{"named inline value", func(d *fm.Data) { d.Addresses[0].Name = "client" }, plan.ErrRender},
		{"non-inline value", func(d *fm.Data) { d.Addresses[0].Inline = false }, plan.ErrRender},
		{"range differs from literal", func(d *fm.Data) {
			d.Addresses[0].Ranges[0].Last = netip.MustParseAddr("192.0.2.11")
		}, plan.ErrRender},
		{"unowned inline value", func(d *fm.Data) {
			ip := netip.MustParseAddr("198.51.100.1")
			d.Addresses = append(d.Addresses, fm.AddressRecord{
				Object: fm.Object{ID: "$literal:198.51.100.1", Inline: true},
				Ranges: []flow.AddressRange{{First: ip, Last: ip}},
			})
		}, plan.ErrInvalid},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before, captured := literalNATCaptures(t, "192.0.2.10/32", "any", "")
			data := captured.Export()
			tt.mutate(&data)
			after, err := fm.Seal(data)
			if err != nil || !after.Complete() {
				t.Fatal("invalid test graph", err)
			}
			commands, err := (paloalto.Renderer{}).RenderNative(t.Context(), before, after, literalNATChanges(after))
			if !errors.Is(err, tt.want) || commands != nil {
				t.Fatalf("invalid literal emitted commands: %v, %v", commands, err)
			}
		})
	}
}

func literalNATCaptures(t *testing.T, source, destination, translation string) (*fm.Firewall, *fm.Firewall) {
	t.Helper()
	// This capture is authored independently of the renderer's commands.
	fields := []string{"from any", "to any", "source " + source, "destination " + destination, "service any"}
	if translation != "" {
		fields = append(fields, translation)
	}
	var raw strings.Builder
	for _, field := range fields {
		raw.WriteString("set rulebase nat rules literal " + field + "\n")
	}
	before, err := parseObserved(t.Context(), "")
	if err != nil || !before.Complete() {
		t.Fatal("invalid before capture", err)
	}
	after, err := parseObserved(t.Context(), raw.String())
	if err != nil || !after.Complete() {
		t.Fatal("invalid after capture", err)
	}
	return before, after
}

func literalNATChanges(after *fm.Firewall) plan.NativeChanges {
	data := after.Export()
	return plan.NativeChanges{Additions: plan.NativeAdditions{
		Addresses: data.Addresses, StaticNATs: data.StaticNATs, DynamicNATs: data.DynamicNATs,
	}}
}

package paloalto_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/vendors/paloalto"
)

func TestPANServiceCapacityIncludesProductsAndBuiltins(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		terms        int
	}{
		{"builtins", "", 3},
		{"set", "set service custom protocol tcp source-port 1,2\nset service custom protocol tcp port 80,443\n", 7},
		{"xml", `<config><shared><service><entry name="custom"><protocol><tcp><source-port>1,2</source-port><port>80,443</port></tcp></protocol></entry></service></shared></config>`, 7},
		{"multiple", "set service first protocol tcp source-port 1,2\nset service first protocol tcp port 80,443\nset service second protocol udp source-port 1,2\nset service second protocol udp port 53,123\n", 11},
		{"overridden-builtin", "set service service-http protocol tcp port 80\n", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter := paloalto.Parser{Limits: config.Limits{MaxServiceTerms: tc.terms}}
			fw, err := adapter.Parse(t.Context(), config.Source{Text: tc.source, Complete: true}, fm.Metadata{Device: "pan"})
			if err != nil || !fw.Complete() {
				t.Fatalf("exact service capacity rejected: %v", err)
			}
			count := 0
			for _, service := range fw.Services() {
				count += len(service.Record().Terms)
			}
			if count != tc.terms {
				t.Fatalf("service catalog has %d terms, want %d", count, tc.terms)
			}
			adapter.Limits.MaxServiceTerms--
			fw, err = adapter.Parse(t.Context(), config.Source{Text: tc.source, Complete: true}, fm.Metadata{Device: "pan"})
			if fw != nil || !errors.Is(err, config.ErrSource) {
				t.Fatalf("over-capacity parse published a graph: %v", err)
			}
		})
	}
}

// Checkpoints make cancellation deterministic without sleeps or large inputs.
type serviceCancellation struct {
	context.Context
	remaining int
}

func (c *serviceCancellation) Err() error {
	c.remaining--
	if c.remaining <= 0 {
		return context.Canceled
	}
	return nil
}

func TestPANServiceExpansionChecksCancellation(t *testing.T) {
	var ports []string
	for i := range 256 {
		ports = append(ports, fmt.Sprint(i+1))
	}
	list := strings.Join(ports, ",")
	raw := "set service custom protocol tcp source-port " + list + "\nset service custom protocol tcp port " + list + "\n"
	ctx := &serviceCancellation{Context: t.Context(), remaining: 600}
	fw, err := (paloalto.Parser{}).Parse(ctx, config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "pan"})
	if fw != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("service expansion ignored cancellation: %v", err)
	}
}

package benchmarks_test

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	capturegraph "github.com/gatework/firemon/internal/capture"
	"github.com/gatework/firemon/policy"
)

type retainedParser struct{ firewall *fm.Firewall }

func (p retainedParser) Parse(context.Context, config.Source, fm.Metadata) (*fm.Firewall, error) {
	return p.firewall, nil
}

// CaptureValidation measures validation of an already parsed graph, excluding parsing.
func BenchmarkCaptureValidation(b *testing.B) {
	for _, n := range []int{10, 1000} {
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			fw := benchmarkFirewall(b, n)
			source := config.Source{Text: fw.Export().Raw, Complete: true}
			parser := retainedParser{firewall: fw}
			b.ReportAllocs()
			for b.Loop() {
				got, err := capturegraph.Graph(context.Background(), parser, source, fw.Metadata(), nil, fm.ErrGraph, capturegraph.Diagnostics{})
				if err != nil || got != fw {
					b.Fatalf("capture validation: %v", err)
				}
			}
		})
	}
}

func BenchmarkRouteResolution(b *testing.B) {
	for _, n := range []int{10, 1000} {
		b.Run(fmt.Sprintf("routes=%d", n), func(b *testing.B) {
			d := benchmarkFirewall(b, 10).Export()
			iface := d.Interfaces[1].ID
			for i := range n {
				d.Routes = append(d.Routes, fm.RouteRecord{Object: fm.Object{ID: fm.ID(fmt.Sprintf("bench-route-%d", i))}, Destination: netip.MustParsePrefix(fmt.Sprintf("198.19.%d.%d/32", i>>8, i&255)), NextHop: netip.MustParseAddr("203.0.113.254"), Interface: iface, Metric: 1})
			}
			fw, err := fm.Seal(d)
			if err != nil || !fw.Complete() {
				b.Fatalf("route graph: %v", err)
			}
			interval, _ := flow.PrefixRange(netip.MustParsePrefix("198.19.0.0/16"))
			addresses, _ := flow.NewAddressSet(interval)
			b.ReportAllocs()
			for b.Loop() {
				paths, err := (policy.Engine{}).ResolveRoutes(context.Background(), fw, "", addresses)
				if err != nil || len(paths) != n+1 {
					b.Fatalf("routes=%d: %v", len(paths), err)
				}
			}
		})
	}
}

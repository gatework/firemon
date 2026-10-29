package benchmarks_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/vendors/paloalto"
)

func BenchmarkScan(b *testing.B) {
	for _, tc := range []struct {
		name, text string
		statements int
	}{
		{"short", strings.Repeat("set address host 192.0.2.1\n", 100), 100},
		{"long", "set description \"" + strings.Repeat("防火墙", 1<<16) + "\"\n", 1},
		{"multiline", strings.Repeat("set description \"first\nsecond\"\n", 100), 100},
	} {
		b.Run(tc.name, func(b *testing.B) {
			source := config.Source{Text: tc.text, Complete: true}
			b.ReportAllocs()
			b.SetBytes(int64(len(tc.text)))
			for b.Loop() {
				c, err := config.NewCursor(context.Background(), source, config.Limits{})
				if err != nil {
					b.Fatal(err)
				}
				statements, err := config.Statements(context.Background(), c)
				if err != nil || len(statements) != tc.statements {
					b.Fatalf("scan: %d, %v", len(statements), err)
				}
			}
		})
	}
}

func BenchmarkParseXML(b *testing.B) {
	for _, n := range []int{10, 1000} {
		b.Run(fmt.Sprintf("addresses=%d", n), func(b *testing.B) {
			var source strings.Builder
			source.WriteString("<config><shared><address>")
			for i := range n {
				fmt.Fprintf(&source, "<entry name=\"host-%d\"><ip-netmask>198.18.%d.%d/32</ip-netmask></entry>", i, i>>8, i&255)
			}
			source.WriteString("</address></shared></config>")
			raw := config.Source{Text: source.String(), Complete: true}
			b.ReportAllocs()
			b.SetBytes(int64(len(raw.Text)))
			for b.Loop() {
				fw, err := paloalto.Parse(context.Background(), raw, fm.Metadata{Device: "synthetic-benchmark", Software: "10.2.0"})
				if err != nil {
					b.Fatal(err)
				}
				if !fw.Complete() || len(fw.Addresses()) != n {
					b.Fatal(fw.Diagnostics())
				}
			}
		})
	}
}

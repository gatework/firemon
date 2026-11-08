package benchmarks_test

import (
	"context"
	"fmt"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/vendors/fortinet"
	"strings"
	"testing"
)

// Large topology catches accidental per-policy copies of entire record tables;
// the ordinary rule-count matrix deliberately has only two interfaces.
func BenchmarkFortinetTopology(b *testing.B) {
	var source strings.Builder
	source.WriteString("config system interface\n")
	for i := range 500 {
		fmt.Fprintf(&source, "edit port%d\nset ip 198.18.%d.%d 255.255.255.255\nnext\n", i, i/256, i%256)
	}
	source.WriteString("end\nconfig firewall policy\n")
	for i := range 1000 {
		fmt.Fprintf(&source, "edit %d\nset srcintf port0\nset dstintf port1\nset srcaddr all\nset dstaddr all\nset service ALL\nset schedule always\nset action accept\nnext\n", i+1)
	}
	source.WriteString("end\n")
	raw := config.Source{Text: source.String(), Complete: true}
	b.ReportAllocs()
	b.SetBytes(int64(len(raw.Text)))
	for b.Loop() {
		fw, err := (fortinet.Parser{}).Parse(context.Background(), raw, fm.Metadata{Device: "synthetic-topology", Software: "7.4.0"})
		if err != nil {
			b.Fatal(err)
		}
		if !fw.Complete() || len(fw.Interfaces()) != 500 || fw.RuleCount() < 1000 {
			b.Fatal("incomplete topology", fw.Diagnostics())
		}
	}
}

package benchmarks_test

import (
	"context"
	"fmt"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func BenchmarkParse(b *testing.B) {
	for _, vendor := range parsers {
		for _, n := range []int{10, 100, 1000} {
			b.Run(fmt.Sprintf("%s/rules=%d", vendor.name, n), func(b *testing.B) {
				source := config.Source{Text: nativeConfig(vendor.name, n), Complete: true}
				metadata := fm.Metadata{Device: "synthetic-benchmark", Software: "7.4.0"}
				ctx := context.Background()
				b.ReportAllocs()
				b.SetBytes(int64(len(source.Text)))
				for b.Loop() {
					fw, err := vendor.parse(ctx, source, metadata)
					if err != nil {
						b.Fatal(err)
					}
					if !fw.Complete() || len(fw.Rules()) < n {
						b.Fatal(fw.Diagnostics())
					}
				}
			})
		}
	}
}

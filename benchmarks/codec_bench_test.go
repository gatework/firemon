package benchmarks_test

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/gatework/firemon/snapshot"
)

func BenchmarkSnapshot(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		fw := benchmarkFirewall(b, n)
		var data bytes.Buffer
		if err := snapshot.Encode(&data, fw); err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("encode/rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(data.Len()))
			for b.Loop() {
				if err := snapshot.Encode(io.Discard, fw); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("decode/rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(data.Len()))
			for b.Loop() {
				loaded, err := snapshot.Decode(bytes.NewReader(data.Bytes()), snapshot.DefaultMaxBytes)
				if err != nil {
					b.Fatal(err)
				}
				if loaded.SemanticDigest() != fw.SemanticDigest() {
					b.Fatal("semantic roundtrip changed")
				}
			}
		})
	}
}

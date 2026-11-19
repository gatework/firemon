package oracle_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// BenchmarkWide_Corpus measures the widest requests on every device of the
// private corpus: any to any on every port, queried and then designed with
// an override, the shape that once took minutes. Names only, no contents
// (TST-3). Run with FIREMON_CORPUS set.
func BenchmarkWide_Corpus(b *testing.B) {
	dir := os.Getenv("FIREMON_CORPUS")
	if dir == "" {
		b.Skip("FIREMON_CORPUS not set")
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		b.Fatal(err)
	}
	var devices []device
	for _, path := range paths {
		if d, ok := loadDevice(b, path); ok {
			devices = append(devices, d)
		}
	}
	if len(devices) == 0 {
		b.Skip("no firewall configuration in the corpus")
	}
	svc, _ := traffic.ParseServiceSet("tcp/1-65535")
	in := design.Intent{Src: traffic.AnyAddress(), Dst: traffic.AnyAddress(), Service: svc, Override: true}
	now := func() time.Time { return at }
	b.Run("query", func(b *testing.B) {
		for b.Loop() {
			for _, d := range devices {
				if _, err := query.New(d.fw, query.Options{Now: now}).Query(query.Request{Src: in.Src, Dst: in.Dst, Service: svc}); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("block", func(b *testing.B) {
		for b.Loop() {
			for _, d := range devices {
				if _, err := design.New(d.fw, design.Options{Now: now}).PlanBlock(design.Intent{Dst: in.Dst, Service: svc}); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
}

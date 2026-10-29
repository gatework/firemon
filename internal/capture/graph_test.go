package capture

import (
	"context"
	"errors"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"testing"
	"time"
)

type parseFunc func(context.Context, config.Source, fm.Metadata) (*fm.Firewall, error)

func (f parseFunc) Parse(c context.Context, s config.Source, m fm.Metadata) (*fm.Firewall, error) {
	return f(c, s, m)
}
func TestFailurePreservesOriginalEvidenceAndError(t *testing.T) {
	sentinel := errors.New("secret parser error")
	invalid := errors.New("invalid")
	for _, mode := range []string{"parse", "cancel", "identity", "source", "software", "captured-at", "cancel-during-parse", "transport", "partial"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			source := config.Source{Text: "original", Complete: true}
			meta := fm.Metadata{Device: "fw", Vendor: "hillstone", Software: "one", CapturedAt: time.Date(2026, 10, 29, 1, 2, 3, 0, time.UTC)}
			if mode == "cancel" {
				cancel()
			}
			if mode == "partial" {
				source.Complete = false
			}
			parser := parseFunc(func(_ context.Context, s config.Source, m fm.Metadata) (*fm.Firewall, error) {
				if mode == "parse" {
					return nil, sentinel
				}
				if mode == "identity" {
					m.Device = "spoof"
				}
				if mode == "software" {
					m.Software = "spoof"
				}
				if mode == "captured-at" {
					m.CapturedAt = m.CapturedAt.Add(time.Second)
				}
				if mode == "cancel-during-parse" {
					cancel()
				}
				if mode == "source" {
					s.Text = "spoof"
				}
				return fm.Seal(fm.Data{Metadata: m, Raw: s.Text})
			})
			var prior error
			if mode == "transport" {
				prior = sentinel
				parser = parseFunc(func(context.Context, config.Source, fm.Metadata) (*fm.Firewall, error) {
					t.Fatal("parsed failed transport capture")
					return nil, nil
				})
			}
			fw, err := Graph(ctx, parser, source, meta, prior, invalid, Diagnostics{Failed: fm.Diagnostic{Code: "fixed", Message: "fixed"}, Incomplete: fm.Diagnostic{Code: "partial", Message: "partial"}})
			if fw == nil || fw.Complete() || fw.Export().Raw != "original" || !sameMetadata(fw.Metadata(), meta) {
				t.Fatalf("lost original incomplete evidence: %v %v", fw, err)
			}
			if (mode == "parse" || mode == "transport") && !errors.Is(err, sentinel) {
				t.Fatalf("lost parse error: %v", err)
			}
			if (mode == "cancel" || mode == "cancel-during-parse") && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
			if mode != "partial" && err == nil {
				t.Fatal("failure lost")
			}
			for _, d := range fw.Diagnostics() {
				if d.Message == sentinel.Error() {
					t.Fatal("persisted parser error")
				}
			}
		})
	}
}

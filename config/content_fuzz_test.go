package config_test

import (
	"context"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"strings"
	"testing"
)

func FuzzContentSourceOwnership(f *testing.F) {
	for _, seed := range []string{"", "set address host 192.0.2.1\n", "description \"first\nsecond\"\r\n", "中文\rnext\n", "<config><address><entry name=\"a\">192.0.2.1</entry></address></config>", "<a>\r\n<b/>\r</a>", "\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 64<<10 {
			t.Skip()
		}
		ctx := context.Background()
		limits := config.Limits{MaxBytes: 64 << 10, MaxLines: 2048, MaxDepth: 32}
		source := config.Source{Text: raw, Complete: true}
		check := func(content *config.Content) {
			var joined strings.Builder
			for _, line := range content.Lines() {
				joined.WriteString(line.Raw)
			}
			if joined.String() != raw {
				t.Fatal("content lost source bytes")
			}
			for _, e := range content.Evidence() {
				if e.State != fm.Pending {
					t.Fatal("reading claimed evidence")
				}
			}
		}
		if content, err := config.NewContent(ctx, source, limits); err == nil {
			check(content)
			if rows, err := config.Statements(ctx, content); err == nil {
				var joined strings.Builder
				for _, row := range rows {
					joined.WriteString(row.Raw)
				}
				if joined.String() != raw {
					t.Fatal("statements lost source bytes")
				}
				check(content)
			}
		}
		if strings.HasPrefix(strings.TrimSpace(raw), "<") {
			if doc, err := config.XML(ctx, source, limits); err == nil {
				check(doc.Content)
			}
		}
	})
}

package cli

import (
	"testing"
	"unicode"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func hasHan(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

// Every command and flag explains itself in Chinese.
func TestHelpIsChinese(t *testing.T) {
	t.Parallel()
	root := newRoot(t.Context(), &Deps{Getenv: func(string) string { return "" }})
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if !hasHan(c.Short) {
			t.Errorf("command %q: short help %q", c.CommandPath(), c.Short)
		}
		if c.Long != "" && !hasHan(c.Long) {
			t.Errorf("command %q: long help is not Chinese", c.CommandPath())
		}
		check := func(f *pflag.Flag) {
			if !hasHan(f.Usage) {
				t.Errorf("command %q: flag --%s %q", c.CommandPath(), f.Name, f.Usage)
			}
		}
		c.LocalFlags().VisitAll(check)
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}

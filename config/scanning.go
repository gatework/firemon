package config

import (
	"context"
	"unicode/utf8"
)

// scanChunk bounds work between cancellation checks in source byte scans. UTF-8
// validation moves a boundary back by at most one rune, never splitting a rune.
const scanChunk = 4096

func validateSource(ctx context.Context, source Source, limits Limits) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(source.Text) > limits.MaxBytes {
		return ErrSource
	}
	for start := 0; start < len(source.Text); {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := min(start+scanChunk, len(source.Text))
		if end < len(source.Text) {
			for offset := 0; offset < utf8.UTFMax && end > start && !utf8.RuneStart(source.Text[end]); offset++ {
				end--
			}
		}
		if end <= start || !utf8.ValidString(source.Text[start:end]) {
			return ErrSource
		}
		start = end
	}
	return ctx.Err()
}

package config

import (
	"testing"

	fm "github.com/gatework/firemon"
)

func TestSpanLocatesPhysicalLinesAcrossByteBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		raw   string
		spans []fm.Span
	}{
		{
			name: "split utf8",
			raw:  "界\r\nlast",
			spans: []fm.Span{
				{First: 1, Last: 1, StartByte: 0, EndByte: 1},
				{First: 1, Last: 1, StartByte: 1, EndByte: 5},
				{First: 2, Last: 2, StartByte: 5, EndByte: 9},
			},
		},
		{
			name: "split line endings",
			raw:  "a\r\nb\rc\n",
			spans: []fm.Span{
				{First: 1, Last: 1, StartByte: 0, EndByte: 2},
				{First: 1, Last: 2, StartByte: 2, EndByte: 5},
				{First: 3, Last: 3, StartByte: 5, EndByte: 7},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newContent(t.Context(), Source{Text: tc.raw}, Limits{})
			if err != nil {
				t.Fatal(err)
			}
			for _, expected := range tc.spans {
				if got, ok := c.span(expected.StartByte, expected.EndByte); !ok || got != expected {
					t.Fatalf("span = %+v, %v; want %+v", got, ok, expected)
				}
			}
			for _, bounds := range [][2]int{{-1, 1}, {0, 0}, {2, 1}, {0, len(tc.raw) + 1}} {
				if _, ok := c.span(bounds[0], bounds[1]); ok {
					t.Fatalf("invalid span accepted: %v", bounds)
				}
			}
		})
	}
}

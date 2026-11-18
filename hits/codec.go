package hits

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// ErrFormat reports counters that cannot be read.
var ErrFormat = errors.New("hits: invalid counters")

// Decode reads counters exported by another tool: the JSON form of a
// Snapshot, or CSV with a header naming the columns rule, hits and
// optionally last_hit, first_hit, reset (RFC 3339). taken and since
// describe a CSV export, which carries neither.
func Decode(r io.Reader, taken, since time.Time) (Snapshot, error) {
	body, err := io.ReadAll(io.LimitReader(r, 64<<20))
	if err != nil {
		return Snapshot{}, err
	}
	text := strings.TrimSpace(string(body))
	if strings.HasPrefix(text, "{") {
		var s Snapshot
		if err := json.Unmarshal(body, &s); err != nil {
			return Snapshot{}, fmt.Errorf("%w: %w", ErrFormat, err)
		}
		return s, nil
	}
	return decodeCSV(text, taken, since)
}

func decodeCSV(text string, taken, since time.Time) (Snapshot, error) {
	rows, err := csv.NewReader(strings.NewReader(text)).ReadAll()
	if err != nil || len(rows) < 2 {
		return Snapshot{}, fmt.Errorf("%w: CSV needs a header and rows", ErrFormat)
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	ri, okR := col["rule"]
	hi, okH := col["hits"]
	if !okR || !okH {
		return Snapshot{}, fmt.Errorf("%w: CSV needs rule and hits columns", ErrFormat)
	}
	s := Snapshot{Taken: taken, Since: since}
	for n, row := range rows[1:] {
		if len(row) <= max(ri, hi) {
			return Snapshot{}, fmt.Errorf("%w: row %d is short", ErrFormat, n+2)
		}
		h, err := strconv.ParseUint(strings.TrimSpace(row[hi]), 10, 64)
		if err != nil {
			return Snapshot{}, fmt.Errorf("%w: row %d: %w", ErrFormat, n+2, err)
		}
		c := Counter{Rule: strings.TrimSpace(row[ri]), Hits: h}
		for name, dst := range map[string]*time.Time{"last_hit": &c.LastHit, "first_hit": &c.FirstHit, "reset": &c.Reset} {
			if i, ok := col[name]; ok && i < len(row) && strings.TrimSpace(row[i]) != "" {
				t, err := time.Parse(time.RFC3339, strings.TrimSpace(row[i]))
				if err != nil {
					return Snapshot{}, fmt.Errorf("%w: row %d %s: %w", ErrFormat, n+2, name, err)
				}
				*dst = t
			}
		}
		s.Counters = append(s.Counters, c)
	}
	return s, nil
}

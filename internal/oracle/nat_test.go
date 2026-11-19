package oracle_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// natRoundTrip looks every one-host static mapping and destination NAT up
// from both ends: the internal address must show the public one it is
// published at, and the public address the internal one it maps to.
func natRoundTrip(t *testing.T, fw *firemon.Firewall) (checked int, failures []string) {
	t.Helper()
	e := query.New(fw, query.Options{Now: func() time.Time { return at }})
	find := func(uses []query.NATUse, id string, role query.NATRole, ok func(query.NATUse) bool) bool {
		return slices.ContainsFunc(uses, func(u query.NATUse) bool { return u.ID == id && u.Role == role && ok(u) })
	}
	for _, m := range fw.StaticNATs() {
		if !m.Enabled() {
			continue
		}
		inside, mapped := m.Real(), m.Mapped()
		if _, ok := inside.Single(); !ok {
			continue
		}
		checked++
		id := m.Spec().ID
		if !find(e.NATLookup(inside, noService), id, query.NATRolePublished, func(u query.NATUse) bool { return u.Match.Dst.Equal(mapped) }) {
			failures = append(failures, fmt.Sprintf("static %s: %s is not shown published at %s", id, inside, mapped))
		}
		if !find(e.NATLookup(mapped, noService), id, query.NATRoleInbound, func(u query.NATUse) bool { return u.Translated.Equal(inside) }) {
			failures = append(failures, fmt.Sprintf("static %s: %s is not shown mapped to %s", id, mapped, inside))
		}
	}
	for _, r := range fw.NATRulesFor(firemon.NATKindDestination) {
		inner := r.Translated(firemon.NATKindDestination)
		if r.Spec().Disabled || !r.Decidable() || r.Exempts() {
			continue
		}
		if _, ok := inner.Single(); !ok {
			continue
		}
		public := r.Match().Dst
		checked++
		id := r.Spec().ID
		if !find(e.NATLookup(inner, noService), id, query.NATRolePublished, func(u query.NATUse) bool { return u.Match.Dst.Equal(public) }) {
			failures = append(failures, fmt.Sprintf("dnat %s: %s is not shown published at %s", id, inner, public))
		}
		if !find(e.NATLookup(public, noService), id, query.NATRoleInbound, func(u query.NATUse) bool { return u.Translated.Equal(inner) }) {
			failures = append(failures, fmt.Sprintf("dnat %s: %s is not shown translated to %s", id, public, inner))
		}
	}
	return checked, failures
}

func TestNATRoundTrip_Fixtures(t *testing.T) {
	t.Parallel()
	total := 0
	for _, path := range []string{
		filepath.Join("..", "..", "vendors", "hillstone", "testdata", "basic.conf"),
		filepath.Join("..", "..", "vendors", "paloalto", "testdata", "basic.conf"),
	} {
		d, ok := loadDevice(t, path)
		if !ok {
			t.Fatal("fixture not recognised")
		}
		checked, failures := natRoundTrip(t, d.fw)
		total += checked
		for _, f := range failures {
			t.Error(f)
		}
	}
	if total == 0 {
		t.Fatal("nothing checked")
	}
}

// TestNATRoundTrip_Corpus runs the round trip on the private corpus; it
// prints counts and rule ids only (TST-3).
func TestNATRoundTrip_Corpus(t *testing.T) {
	t.Parallel()
	dir := os.Getenv("FIREMON_CORPUS")
	if dir == "" {
		t.Skip("FIREMON_CORPUS not set")
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			d, ok := loadDevice(t, path)
			if !ok {
				t.Skip("not a firewall configuration")
			}
			checked, failures := natRoundTrip(t, d.fw)
			t.Logf("nat entries checked=%d failures=%d", checked, len(failures))
			for _, f := range failures[:min(len(failures), 10)] {
				t.Error(f)
			}
		})
	}
}

// noService looks up every service.
var noService traffic.ServiceSet

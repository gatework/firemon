package oracle_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/internal/bootstrap"
	"github.com/gatework/firemon/internal/oracle"
	"github.com/gatework/firemon/migrate"
)

// migrateLoop translates a configuration to the other vendor, reads the
// rendered target back, and decides the boundary packets of every source
// rule on both. Where the source decision is settled and every rule that
// could take part in it translated exactly, the target must decide the
// same action: the migrated policy behaves as the source, first match
// included.
func migrateLoop(t *testing.T, d device) (compared, explained int, failures []string) {
	t.Helper()
	src := d.fw.Config()
	to := firemon.VendorPaloAlto
	if src.Vendor == firemon.VendorPaloAlto {
		to = firemon.VendorHillstone
	}
	p, err := bootstrap.Lookup(to, time.UTC, nil)
	if err != nil {
		t.Fatal(err)
	}
	target, err := bootstrap.MigrationTarget(p)
	if err != nil {
		t.Fatal(err)
	}
	res, err := migrate.Translate(src, migrate.Mapping{}, target)
	if err != nil {
		t.Fatal(err)
	}
	script, err := p.Render(res.Plan)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(script.Commands, "\n") + "\n"
	if to == firemon.VendorPaloAlto {
		text = panApply("", script.Commands)
	}
	backCfg, err := p.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	back, err := firemon.Compile(backCfg)
	if err != nil {
		t.Fatal(err)
	}
	exact := map[string]bool{}    // source rule IDs translated exactly
	origin := map[string]string{} // target rule ID -> source rule ID
	for _, it := range res.Items {
		if it.Kind != migrate.ItemKindRule && it.Kind != migrate.ItemKindDefault {
			continue
		}
		exact[it.Source] = it.Fidelity == migrate.FidelityExact
		for _, id := range it.Target {
			origin[id] = it.Source
		}
	}
	zones := zoneNames(d.fw)
	for _, r := range d.fw.Rules() {
		if r.Ignored() {
			continue
		}
		for _, pkt := range boundaryPackets(r, zones) {
			vs := oracle.Decide(d.fw, pkt, at)
			if !vs.Settled() {
				continue
			}
			vt := oracle.Decide(back, pkt, at)
			if vt.Action() == vs.Action() && vt.Settled() {
				compared++
				continue
			}
			if why := explain(d.fw, pkt, vs, vt, exact, origin); why != "" {
				explained++
				continue
			}
			if len(failures) < 10 {
				failures = append(failures, fmt.Sprintf("packet %v: source %s %s, target %s (from %s) %s settled %v",
					pkt, name(vs.Rule), vs.Action(), name(vt.Rule), origin[ruleID(vt.Rule)], vt.Action(), vt.Settled()))
			}
		}
	}
	return compared, explained, failures
}

// explain returns why a differing decision is expected: a rule that takes
// part in either decision, or one above that may match the packet, was
// not translated exactly.
func explain(src *firemon.Firewall, p oracle.Packet, vs, vt oracle.Verdict, exact map[string]bool, origin map[string]string) string {
	if vs.Rule != nil && !exact[vs.Rule.ID()] {
		return "source rule not exact"
	}
	if vt.Rule != nil {
		o, ok := origin[vt.Rule.ID()]
		if !ok || !exact[o] {
			return "target rule from a rule not exact"
		}
	}
	for _, r := range vt.Possible {
		if o, ok := origin[r.ID()]; !ok || !exact[o] {
			return "possible target rule not exact"
		}
	}
	svc := p.Service()
	for _, r := range src.Rules() {
		if vs.Rule != nil && r.Position() >= vs.Rule.Position() {
			break
		}
		if !exact[r.ID()] && !r.Ignored() {
			b := r.Bound()
			if b.Src.Contains(p.Src) && b.Dst.Contains(p.Dst) && b.Service.ContainsSet(svc) {
				return "a rule above, not exact, may match"
			}
		}
	}
	return ""
}

func ruleID(r *firemon.Rule) string {
	if r == nil {
		return ""
	}
	return r.ID()
}

// TestMigrateLoop_Corpus proves translations on every configuration of
// the private corpus; it prints counts and rule ids only (TST-3).
func TestMigrateLoop_Corpus(t *testing.T) {
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
			compared, explained, failures := migrateLoop(t, d)
			t.Logf("same=%d explained=%d failures=%d", compared, explained, len(failures))
			for _, f := range failures {
				t.Error(f)
			}
		})
	}
}

func TestMigrateLoop_Fixtures(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		filepath.Join("..", "..", "vendors", "paloalto", "testdata", "basic.conf"),
	} {
		d, ok := loadDevice(t, path)
		if !ok {
			t.Fatal("fixture not recognised")
		}
		compared, explained, failures := migrateLoop(t, d)
		t.Logf("same=%d explained=%d", compared, explained)
		for _, f := range failures {
			t.Error(f)
		}
		if compared == 0 {
			t.Error("nothing compared")
		}
	}
}

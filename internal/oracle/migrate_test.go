package oracle_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/internal/bootstrap"
	"github.com/gatework/firemon/internal/oracle"
	"github.com/gatework/firemon/migrate"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
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
			// A deny is never weakened: what a source deny rule blocks the
			// target does not permit, whatever the fidelity of the rules.
			if denied := vs.Rule != nil && vs.Action() == firemon.ActionDeny; denied && vt.Action() == firemon.ActionPermit &&
				!slices.Contains(res.DisabledDenies, ruleID(vs.Rule)) {
				failures = append(failures, fmt.Sprintf("packet %v: denied by source rule %s, permitted on the target by %s (from %s)",
					pkt, name(vs.Rule), name(vt.Rule), origin[ruleID(vt.Rule)]))
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
	natExact := map[string]bool{}
	for _, it := range res.Items {
		if it.Kind == migrate.ItemKindNAT {
			natExact[it.Source] = it.Fidelity == migrate.FidelityExact
		}
	}
	failures = append(failures, natAgrees(d.fw, back, natExact)...)
	return compared, explained, failures
}

// natAgrees checks that every internal server a source NAT entry
// translated exactly publishes at the same public addresses on the target,
// by looking the server up both before and after.
func natAgrees(src, dst *firemon.Firewall, exact map[string]bool) []string {
	before := query.New(src, query.Options{Now: func() time.Time { return at }})
	after := query.New(dst, query.Options{Now: func() time.Time { return at }})
	published := func(e *query.Engine, addr traffic.AddressSet) []string {
		var out []string
		for _, u := range e.NATLookup(addr, traffic.ServiceSet{}) {
			if u.Role == query.NATRolePublished && u.State == query.NATStateActive {
				if s := u.Match.Dst.String(); !slices.Contains(out, s) {
					out = append(out, s)
				}
			}
		}
		slices.Sort(out)
		return out
	}
	var failures []string
	check := func(id string, inside traffic.AddressSet) {
		if !exact[id] {
			return
		}
		if _, ok := inside.Single(); !ok {
			return
		}
		b, a := published(before, inside), published(after, inside)
		if !slices.Equal(a, b) {
			failures = append(failures, fmt.Sprintf("nat %s: %s published at %v, after migration at %v", id, inside, b, a))
		}
	}
	for _, r := range src.NATRulesFor(firemon.NATKindDestination) {
		if !r.Spec().Disabled && r.Decidable() && !r.Exempts() {
			check(r.Spec().ID, r.Translated(firemon.NATKindDestination))
		}
	}
	for _, m := range src.StaticNATs() {
		if m.Enabled() {
			check(m.Spec().ID, m.Real())
		}
	}
	return failures
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

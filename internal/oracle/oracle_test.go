package oracle_test

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/internal/oracle"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
	"github.com/gatework/firemon/vendors/hillstone"
	"github.com/gatework/firemon/vendors/paloalto"
)

var at = time.Date(2026, 11, 18, 10, 30, 0, 0, time.UTC)

// stats counts what a cross-check covered.
type stats struct {
	packets, agreed, skipped int
	mismatches               []string
}

// crossCheck asks the engine and the oracle about boundary packets of
// every rule and records every disagreement.
func crossCheck(fw *firemon.Firewall, maxMismatches int) stats {
	engine := query.New(fw, query.Options{Now: func() time.Time { return at }})
	zones := zoneNames(fw)
	var st stats
	for _, r := range fw.Rules() {
		if r.Ignored() {
			continue
		}
		for _, p := range boundaryPackets(r, zones) {
			st.packets++
			msg, ok, skipped := compare(fw, engine, r, p)
			switch {
			case skipped:
				st.skipped++
			case ok:
				st.agreed++
			case len(st.mismatches) < maxMismatches:
				st.mismatches = append(st.mismatches, msg)
			default:
				st.mismatches = append(st.mismatches[:maxMismatches], "...")
			}
		}
	}
	return st
}

// compare evaluates one packet both ways. Packets the engine translates
// are compared as the policy sees them; packets it cannot pin to one
// point after translation are skipped.
func compare(fw *firemon.Firewall, engine *query.Engine, r *firemon.Rule, p oracle.Packet) (msg string, ok, skipped bool) {
	res, err := engine.Query(query.Request{
		// The oracle models application rules as possible matches: compare
		// with the strict engine (ADR 0017 inference is tested in query).
		Src: host(p.Src), Dst: host(p.Dst), Service: p.Service(), FromZone: p.From, ToZone: p.To, At: at, Strict: true,
	})
	if err != nil {
		return fmt.Sprintf("rule %s %v: engine error %v", r.ID(), p, err), false, false
	}
	if res.Incomplete || len(res.Paths) != 1 {
		return "", false, true
	}
	path := res.Paths[0]
	if len(path.NATUncertain) > 0 || len(path.Conditions) > 0 {
		return "", false, true
	}
	policy, single := point(path.Policy, p)
	if !single {
		return "", false, true
	}
	// Translation can move the packet to other zones: the policy sees
	// the path's.
	policy.From, policy.To = path.From, path.To
	if len(path.Decisions) != 1 {
		return fmt.Sprintf("rule %s %v: %d decisions for one packet", r.ID(), p, len(path.Decisions)), false, false
	}
	d := path.Decisions[0]
	want := oracle.Decide(fw, policy, at)
	if d.Rule != want.Rule || !slices.Equal(ids(d.Possible), ids(want.Possible)) {
		return fmt.Sprintf("rule %s packet %v: engine %s possible %v, oracle %s possible %v",
			r.ID(), policy, name(d.Rule), ids(d.Possible), name(want.Rule), ids(want.Possible)), false, false
	}
	final := outcome(want)
	if d.FallbackOutcome != final {
		return fmt.Sprintf("packet %v: %s gives %s, want %s", policy, name(d.Rule), d.FallbackOutcome, final), false, false
	}
	if settled := d.Outcome != query.OutcomeUnknown; settled != want.Settled() {
		return fmt.Sprintf("packet %v: engine outcome %s, oracle settled %v (possible %v)", policy, d.Outcome, want.Settled(), ids(want.Possible)), false, false
	}
	return "", true, false
}

// outcome is the engine outcome of an oracle decision.
func outcome(v oracle.Verdict) query.Outcome {
	switch a := v.Action(); {
	case a == firemon.ActionPermit:
		return query.OutcomePermit
	case a == firemon.ActionDeny && v.Rule != nil:
		return query.OutcomeDeny
	case a == firemon.ActionDeny:
		return query.OutcomeDefault
	default:
		return query.OutcomeUnknown
	}
}

// point returns the packet as the policy sees it when the engine's policy
// space is one point.
func point(s traffic.Space, p oracle.Packet) (oracle.Packet, bool) {
	src, ok1 := single(s.Src)
	dst, ok2 := single(s.Dst)
	if !ok1 || !ok2 {
		return p, false
	}
	var svc []traffic.ServiceRange
	for r := range s.Service.All() {
		svc = append(svc, r)
	}
	if len(svc) != 1 || svc[0].ProtocolLow != svc[0].ProtocolHigh || svc[0].Dst.Low != svc[0].Dst.High || svc[0].Src.Low != svc[0].Src.High {
		return p, false
	}
	p.Src, p.Dst = src, dst
	p.Protocol, p.SrcPort, p.DstPort = svc[0].ProtocolLow, svc[0].Src.Low, svc[0].Dst.Low
	return p, true
}

func single(s traffic.AddressSet) (netip.Addr, bool) {
	rs := s.Ranges()
	if len(rs) != 1 || rs[0].From() != rs[0].To() {
		return netip.Addr{}, false
	}
	return rs[0].From(), true
}

func host(a netip.Addr) traffic.AddressSet {
	return traffic.NewAddressSet(netip.PrefixFrom(a, a.BitLen()))
}

func ids(rs []*firemon.Rule) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.ID()
	}
	return out
}

func name(r *firemon.Rule) string {
	if r == nil {
		return "default"
	}
	return "rule " + r.ID()
}

// zoneNames returns the configured zones, or a placeholder when there are
// none: every packet needs a zone pair.
func zoneNames(fw *firemon.Firewall) []string {
	var out []string
	for _, z := range fw.Config().Zones {
		out = append(out, z.Name)
	}
	if len(out) == 0 {
		out = []string{"z"}
	}
	return out
}

// boundaryPackets returns packets on and just outside the edges of a
// rule's match: the first and last address of the first and last range of
// each address dimension, their neighbours, and the edges of the first and
// last service range. Each packet varies one dimension from a packet the
// rule matches, in each zone pair the rule names first.
func boundaryPackets(r *firemon.Rule, zones []string) []oracle.Packet {
	m, _ := r.Certain()
	if m.IsEmpty() {
		m = r.Bound()
	}
	if m.IsEmpty() {
		return nil
	}
	from, to := r.Zones()
	pairs := [][2]string{{first(from, zones[0]), first(to, zones[0])}}
	if len(from) > 1 || len(to) > 1 {
		pairs = append(pairs, [2]string{last(from, zones[len(zones)-1]), last(to, zones[len(zones)-1])})
	}
	if r.Scope() == firemon.ZoneScopeIntra {
		pairs = [][2]string{{pairs[0][0], pairs[0][0]}}
	}
	srcs, dsts := edges(m.Src), edges(m.Dst)
	svcs := serviceEdges(m.Service)
	if len(srcs) == 0 || len(dsts) == 0 || len(svcs) == 0 {
		return nil
	}
	base := oracle.Packet{Src: srcs[0], Dst: dsts[0], Protocol: svcs[0].proto, SrcPort: svcs[0].src, DstPort: svcs[0].dst}
	var out []oracle.Packet
	for _, z := range pairs {
		b := base
		b.From, b.To = z[0], z[1]
		out = append(out, b)
		for _, a := range srcs[1:] {
			p := b
			p.Src = a
			out = append(out, p)
		}
		for _, a := range dsts[1:] {
			p := b
			p.Dst = a
			out = append(out, p)
		}
		for _, s := range svcs[1:] {
			p := b
			p.Protocol, p.SrcPort, p.DstPort = s.proto, s.src, s.dst
			out = append(out, p)
		}
	}
	return out
}

func first(zs []string, fallback string) string {
	if len(zs) == 0 {
		return fallback
	}
	return zs[0]
}

func last(zs []string, fallback string) string {
	if len(zs) == 0 {
		return fallback
	}
	return zs[len(zs)-1]
}

// edges returns an inside address first, then the edges of the first and
// last ranges and their outside neighbours of the same family.
func edges(s traffic.AddressSet) []netip.Addr {
	rs := s.Ranges()
	if len(rs) == 0 {
		return nil
	}
	out := []netip.Addr{rs[0].From()}
	add := func(a netip.Addr) {
		if a.IsValid() && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	for _, r := range []int{0, len(rs) - 1} {
		add(rs[r].To())
		add(rs[r].From().Prev())
		add(rs[r].To().Next())
	}
	return out
}

type svcPoint struct {
	proto    traffic.Protocol
	src, dst uint16
}

// serviceEdges returns a point inside the service first, then the port
// edges of the first and last ranges and their outside neighbours.
func serviceEdges(s traffic.ServiceSet) []svcPoint {
	var rs []traffic.ServiceRange
	for r := range s.All() {
		rs = append(rs, r)
	}
	if len(rs) == 0 {
		return nil
	}
	proto := func(r traffic.ServiceRange) traffic.Protocol {
		if r.ProtocolLow <= traffic.ProtocolTCP && traffic.ProtocolTCP <= r.ProtocolHigh {
			return traffic.ProtocolTCP
		}
		return r.ProtocolLow
	}
	f := rs[0]
	out := []svcPoint{{proto(f), f.Src.Low, f.Dst.Low}}
	add := func(p svcPoint) {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for _, r := range []traffic.ServiceRange{f, rs[len(rs)-1]} {
		p := proto(r)
		add(svcPoint{p, r.Src.Low, r.Dst.High})
		if r.Dst.Low > 0 {
			add(svcPoint{p, r.Src.Low, r.Dst.Low - 1})
		}
		if r.Dst.High < 65535 {
			add(svcPoint{p, r.Src.Low, r.Dst.High + 1})
		}
	}
	return out
}

func compileFile(t *testing.T, path string) (*firemon.Firewall, bool) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	var cfg *firemon.Config
	switch {
	case strings.Contains(text[:min(len(text), 4096)], "\nVersion 5.") || strings.HasSuffix(path, filepath.Join("hillstone", "testdata", "basic.conf")):
		cfg, err = hillstone.New(hillstone.Options{}).Parse(text)
	case strings.Contains(text, "set rulebase security rules "):
		cfg, err = paloalto.New(paloalto.Options{}).Parse(text)
	default:
		return nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return fw, true
}

func report(t *testing.T, st stats) {
	t.Helper()
	t.Logf("packets=%d agreed=%d skipped=%d mismatches=%d", st.packets, st.agreed, st.skipped, len(st.mismatches))
	for _, m := range st.mismatches {
		t.Error(m)
	}
	if st.agreed == 0 {
		t.Error("no packet was compared")
	}
}

// TestOracle_Fixtures cross-checks the engine on the synthetic fixtures.
func TestOracle_Fixtures(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		filepath.Join("..", "..", "vendors", "hillstone", "testdata", "basic.conf"),
		filepath.Join("..", "..", "vendors", "paloalto", "testdata", "basic.conf"),
	} {
		t.Run(filepath.Base(filepath.Dir(filepath.Dir(path))), func(t *testing.T) {
			t.Parallel()
			fw, ok := compileFile(t, path)
			if !ok {
				t.Fatal("fixture not recognised")
			}
			report(t, crossCheck(fw, 20))
		})
	}
}

// TestOracle_Corpus cross-checks the engine on every configuration of the
// private corpus named by FIREMON_CORPUS; it prints aggregate counts and
// rule ids only (TST-3).
func TestOracle_Corpus(t *testing.T) {
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
			fw, ok := compileFile(t, path)
			if !ok {
				t.Skip("not a firewall configuration")
			}
			report(t, crossCheck(fw, 10))
		})
	}
}

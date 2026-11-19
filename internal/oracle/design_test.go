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
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/internal/oracle"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/vendors/hillstone"
	"github.com/gatework/firemon/vendors/paloalto"
)

// device is a parsed configuration with what reads commands back.
type device struct {
	text   string
	fw     *firemon.Firewall
	render func(*design.Plan) (design.Script, error)
	// readback returns the configuration after the commands.
	readback func(cmds []string) (*firemon.Config, error)
}

func loadDevice(t *testing.T, path string) (device, bool) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.HasSuffix(text, "\n") {
		text += "\n" // backups end with the device prompt
	}
	d := device{text: text}
	var cfg *firemon.Config
	switch {
	case strings.Contains(text[:min(len(text), 4096)], "\nVersion 5."):
		p := hillstone.New(hillstone.Options{})
		cfg, err = p.Parse(text)
		d.render = hillstone.Renderer{}.Render
		d.readback = func(cmds []string) (*firemon.Config, error) {
			return p.Parse(text + strings.Join(cmds, "\n") + "\n")
		}
	case strings.Contains(text, "\nset rulebase security rules "):
		p := paloalto.New(paloalto.Options{})
		cfg, err = p.Parse(text)
		d.render = paloalto.Renderer{}.Render
		d.readback = func(cmds []string) (*firemon.Config, error) {
			return p.Parse(panApply(text, cmds))
		}
	default:
		return device{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	if d.fw, err = firemon.Compile(cfg); err != nil {
		t.Fatal(err)
	}
	return d, true
}

// loopResult counts the outcomes of design loops on one firewall.
type loopResult struct {
	designed, unchanged, refused int
	// uncertain counts designs the planner reported as depending on rules
	// it cannot evaluate, as unknown or in a warning.
	uncertain int
	failures  []string
}

// designLoop designs access for denied single packets drawn from rule
// boundaries, then proves each plan: once applied, the packet is allowed;
// packets next to it decide as before; and the rendered commands read back
// to the predicted configuration.
func designLoop(t *testing.T, d device, limit int) loopResult {
	t.Helper()
	engine := query.New(d.fw, query.Options{Now: func() time.Time { return at }})
	planner := design.New(d.fw, design.Options{Now: func() time.Time { return at }})
	zones := zoneNames(d.fw)
	var res loopResult
	var candidates []oracle.Packet
	for _, r := range d.fw.Rules() {
		if r.Ignored() {
			continue
		}
		for _, p := range boundaryPackets(r, zones) {
			if p, ok := denied(engine, p); ok && !slices.Contains(candidates, p) {
				candidates = append(candidates, p)
			}
		}
	}
	step := max(1, len(candidates)/limit)
	for i := 0; i < len(candidates) && res.designed+res.refused < limit; i += step {
		p := candidates[i]
		if msg := proveDesign(d, planner, p, i, &res); msg != "" {
			res.failures = append(res.failures, msg)
		}
	}
	return res
}

// denied returns the packet as the policy sees it when the engine
// certainly denies it on one untranslated path.
func denied(engine *query.Engine, p oracle.Packet) (oracle.Packet, bool) {
	res, err := engine.Query(query.Request{Src: host(p.Src), Dst: host(p.Dst), Service: p.Service(), FromZone: p.From, ToZone: p.To, At: at})
	if err != nil || res.Incomplete || len(res.Paths) != 1 || res.Verdict != query.VerdictDenied {
		return p, false
	}
	path := res.Paths[0]
	if path.DestinationNAT != nil || len(path.SourceNAT) > 0 || len(path.Conditions) > 0 || path.From == "" || path.To == "" {
		return p, false
	}
	p.From, p.To = path.From, path.To
	return p, true
}

func proveDesign(d device, planner *design.Planner, p oracle.Packet, n int, res *loopResult) string {
	intent := design.Intent{
		Src: host(p.Src), Dst: host(p.Dst), Service: p.Service(), FromZone: p.From, ToZone: p.To,
		Name: fmt.Sprintf("ORACLE-%d", n), Override: true,
	}
	plan, err := planner.Plan(intent)
	if err != nil {
		return fmt.Sprintf("%v: plan: %v", p, err)
	}
	switch plan.Status {
	case design.StatusChange:
		res.designed++
	case design.StatusNoChange:
		res.unchanged++
		return fmt.Sprintf("%v: denied, yet the planner sees nothing to change", p)
	case design.StatusConflict, design.StatusIndeterminate, design.StatusUnset:
		res.refused++
		return ""
	}
	predicted := d.fw.Config()
	if err := design.Apply(predicted, plan.Changes); err != nil {
		return fmt.Sprintf("%v: apply: %v", p, err)
	}
	after, err := firemon.Compile(predicted)
	if err != nil {
		return fmt.Sprintf("%v: compile after: %v", p, err)
	}
	switch v := oracle.Decide(after, p, at); {
	case v.Action() != firemon.ActionPermit:
		return fmt.Sprintf("%v: still not permitted after %v (rule %s)", p, plan.Changes, name(v.Rule))
	case !v.Settled() && len(plan.Unknown) == 0 && !warned(plan, v.Possible):
		return fmt.Sprintf("%v: rules %v above may still block, unreported (status %s, warnings %v)", p, ids(v.Possible), plan.Status, plan.Warnings)
	case !v.Settled():
		res.uncertain++
	}
	for _, q := range neighbours(p) {
		before, now := oracle.Decide(d.fw, q, at), oracle.Decide(after, q, at)
		if before.Action() != now.Action() || before.Settled() != now.Settled() {
			return fmt.Sprintf("%v: neighbour %v changed from %s to %s by %v", p, q, before.Action(), now.Action(), plan.Changes)
		}
	}
	script, err := d.render(plan)
	if err != nil {
		return fmt.Sprintf("%v: render: %v", p, err)
	}
	back, err := d.readback(script.Commands)
	if err != nil {
		return fmt.Sprintf("%v: readback: %v", p, err)
	}
	got, err := firemon.Compile(back)
	if err != nil {
		return fmt.Sprintf("%v: compile readback: %v", p, err)
	}
	if got.Fingerprint() != after.Fingerprint() {
		return fmt.Sprintf("%v: readback differs from the prediction:\n  %s", p, strings.Join(script.Commands, "\n  "))
	}
	return ""
}

// warned reports whether the plan names every rule that may still decide
// first.
func warned(plan *design.Plan, rules []*firemon.Rule) bool {
	text := strings.Join(plan.Warnings, "\n")
	for _, r := range rules {
		if !strings.Contains(text, r.ID()) {
			return false
		}
	}
	return true
}

// neighbours are the packets one step away in each dimension.
func neighbours(p oracle.Packet) []oracle.Packet {
	var out []oracle.Packet
	for _, a := range []netip.Addr{p.Src.Prev(), p.Src.Next()} {
		if a.IsValid() {
			q := p
			q.Src = a
			out = append(out, q)
		}
	}
	for _, a := range []netip.Addr{p.Dst.Prev(), p.Dst.Next()} {
		if a.IsValid() {
			q := p
			q.Dst = a
			out = append(out, q)
		}
	}
	if p.DstPort > 0 {
		q := p
		q.DstPort--
		out = append(out, q)
	}
	if p.DstPort < 65535 {
		q := p
		q.DstPort++
		out = append(out, q)
	}
	return out
}

func reportLoop(t *testing.T, r loopResult) {
	t.Helper()
	t.Logf("designed=%d uncertain=%d unchanged=%d refused=%d failures=%d", r.designed, r.uncertain, r.unchanged, r.refused, len(r.failures))
	for _, f := range r.failures {
		t.Error(f)
	}
}

func TestDesignLoop_Fixtures(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		filepath.Join("..", "..", "vendors", "paloalto", "testdata", "basic.conf"),
	} {
		d, ok := loadDevice(t, path)
		if !ok {
			t.Fatal("fixture not recognised")
		}
		r := designLoop(t, d, 10)
		reportLoop(t, r)
		if r.designed == 0 {
			t.Error("nothing was designed")
		}
	}
}

// TestDesignLoop_Corpus proves designs on every configuration of the
// private corpus; it prints counts and synthetic rule names only (TST-3).
func TestDesignLoop_Corpus(t *testing.T) {
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
			reportLoop(t, designLoop(t, d, 12))
		})
	}
}

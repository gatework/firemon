package huawei_test

import (
	"context"
	"strings"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/huawei"
)

func mustTraffic(t *testing.T, b flow.Box) flow.Traffic {
	t.Helper()
	v, err := flow.NewTraffic(8, b)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A simulated display-current-configuration capture retains native indentation
// and # boundaries. Move commands are deliberately not applied here: tests place
// the new policy independently and also verify the incorrect position is rejected.
func displayCommands(t *testing.T, commands []string) string {
	t.Helper()
	var out strings.Builder
	depth := 0
	for _, c := range commands {
		switch {
		case c == "system-view" || c == "return":
		case strings.HasPrefix(c, "rule move "):
		case c == "quit":
			depth--
			if depth < 0 {
				t.Fatal("unbalanced quit")
			}
			if depth == 0 {
				out.WriteString("#\n")
			}
		case c == "security-policy":
			out.WriteString(c + "\n")
			depth++
		case strings.HasPrefix(c, "ip address-set ") || strings.HasPrefix(c, "ip service-set "):
			out.WriteString(c + "\n")
			depth++
		case strings.HasPrefix(c, "rule name "):
			out.WriteString(" " + c + "\n")
			depth++
		default:
			out.WriteString(strings.Repeat(" ", depth) + c + "\n")
		}
	}
	if depth != 0 {
		t.Fatal("open native view")
	}
	return out.String()
}
func TestCreatePlanPreservesNativePolicyOrderAndIndependentReadback(t *testing.T) {
	ctx := context.Background()
	raw := strings.Replace(basic, " rule name allow-web", " rule name stop\n  action deny\n rule name allow-web", 1)
	before := parse(t, raw)
	q := policy.Request{FromZone: "trust", ToZone: "untrust", Traffic: traffic(t, "192.0.2.11/32", "203.0.113.11/32", 6, 1234, 8443)}
	p, err := (plan.Planner{Renderer: huawei.Renderer{}}).Plan(ctx, before, []policy.Request{q})
	if err != nil {
		t.Fatal(err)
	}
	moved := false
	for _, c := range p.Commands() {
		if strings.HasPrefix(c, "rule move ") && strings.HasSuffix(c, " before \"stop\"") {
			moved = true
		}
	}
	if !moved {
		t.Fatal("new permit must precede deny", p.Commands())
	}
	created := displayCommands(t, p.Commands())
	// Objects may follow references; the native rule order is the observable result.
	if _, err := p.Verify(ctx, parse(t, created+raw)); err != nil {
		t.Fatal(err, p.Commands())
	}
	if _, err := p.Verify(ctx, parse(t, raw+created)); err == nil {
		t.Fatal("wrong device rule position passed")
	}
}
func TestAppendCommandsPreserveAllExistingMembers(t *testing.T) {
	ctx := context.Background()
	raw := strings.Replace(basic, " service 1 protocol udp source-port 2000 destination-port 53\n", "", 1)
	q := policy.Request{FromZone: "trust", ToZone: "untrust", Traffic: traffic(t, "192.0.2.11/32", "203.0.113.10/32", 6, 1000, 443)}
	// Request the existing complete source-port term so an address append is exact.
	b := q.Traffic.Boxes()[0]
	b.SourcePort.High = 1001
	q.Traffic = mustTraffic(t, b)
	p, err := (plan.Planner{Renderer: huawei.Renderer{}}).Plan(ctx, parse(t, raw), []policy.Request{q})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Changes()) != 1 || p.Changes()[0].Kind != plan.AppendMembers {
		t.Fatal(p.Changes())
	}
	if _, err := p.Verify(ctx, parse(t, raw+displayCommands(t, p.Commands()))); err != nil {
		t.Fatal(err, p.Commands())
	}
}
func TestDisabledRuleRemovalReadbackAndUnsafeNames(t *testing.T) {
	ctx := context.Background()
	before := parse(t, strings.Replace(basic, "  action permit", "  action permit\n  disable", 1))
	after := parse(t, strings.Replace(basic, " rule name allow-web\n  source-zone trust\n  destination-zone untrust\n  source-address address-set clients\n  destination-address 203.0.113.10 mask 32\n  service paired\n  action permit\n", "", 1))
	p, err := (plan.Planner{Renderer: huawei.Renderer{}}).Preserve(ctx, before, after, []plan.Change{{Kind: plan.RemoveRule, Rule: "allow-web"}}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(p.Commands(), "\n"), "undo rule name \"allow-web\"") {
		t.Fatal(p.Commands())
	}
	if _, err := p.Verify(ctx, after); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bad\nreturn", "bad\"name", "bad\\name"} {
		d := after.Export()
		d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: fm.ID(name), Name: name}, Ranges: before.Address("host").Record().Ranges})
		bad, err := fm.Seal(d)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (huawei.Renderer{}).Render(ctx, after, bad, nil); err == nil {
			t.Fatal("unsafe command name accepted")
		}
	}
}

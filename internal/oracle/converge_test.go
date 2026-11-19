package oracle_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/converge"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/internal/oracle"
)

// convergeLoop plans every safe cleanup of a configuration and proves the
// plan without converge's own verifier: the boundary packets of every
// rule decide the same before and after (by the oracle), the commands
// read back to the predicted configuration, and the rollback restores the
// original.
func convergeLoop(t *testing.T, d device) (changes, packets int, failures []string) {
	t.Helper()
	now := func() time.Time { return at }
	rep := converge.Analyze(d.fw, converge.Options{Now: now})
	plan, err := converge.Plan(d.fw, rep, converge.Selection{}, converge.PlanOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) == 0 {
		return 0, 0, nil
	}
	if !plan.Verified {
		return len(plan.Changes), 0, []string{"plan not verified: " + plan.VerifyError}
	}
	predicted := d.fw.Config()
	if err := design.Apply(predicted, plan.Changes); err != nil {
		t.Fatal(err)
	}
	after, err := firemon.Compile(predicted)
	if err != nil {
		t.Fatal(err)
	}
	zones := zoneNames(d.fw)
	for _, r := range d.fw.Rules() {
		if r.Ignored() {
			continue
		}
		for _, p := range boundaryPackets(r, zones) {
			packets++
			before, now := oracle.Decide(d.fw, p, at), oracle.Decide(after, p, at)
			if before.Action() != now.Action() || before.Settled() != now.Settled() {
				if len(failures) < 10 {
					failures = append(failures, fmt.Sprintf("packet %v: %s %s settled %v, after %s %s settled %v",
						p, name(before.Rule), before.Action(), before.Settled(), name(now.Rule), now.Action(), now.Settled()))
				}
			}
		}
	}
	script, err := d.render(plan)
	if err != nil {
		t.Fatal(err)
	}
	back, err := d.readback(script.Commands)
	if err != nil {
		t.Fatal(err)
	}
	if same, err := sameObjects(back, predicted); err != nil || !same {
		failures = append(failures, fmt.Sprintf("readback differs from the prediction (%v)", err))
	}
	restored, err := d.readback(append(script.Commands, script.Rollback...))
	if err != nil {
		t.Fatal(err)
	}
	if same, err := sameObjects(restored, d.fw.Config()); err != nil || !same {
		failures = append(failures, fmt.Sprintf("rollback does not restore the configuration (%v)", err))
	}
	return len(plan.Changes), packets, failures
}

// TestConvergeLoop_Corpus proves cleanups on every configuration of the
// private corpus; it prints counts and rule ids only (TST-3).
func TestConvergeLoop_Corpus(t *testing.T) {
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
			changes, packets, failures := convergeLoop(t, d)
			t.Logf("changes=%d packets=%d failures=%d", changes, packets, len(failures))
			for _, f := range failures {
				t.Error(strings.TrimSpace(f))
			}
		})
	}
}

package deploy_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
)

// The subprocess dies without Close/defer cleanup. Files stand in for device
// running/saved state; the actual snapshot store and journal cross the crash.
type crashDevice struct {
	root, point                      string
	before, after                    *fm.Firewall
	reads, savedReads, writes, saves int
}

func (d *crashDevice) Open(context.Context, string) (deploy.Session, error) { return d, nil }
func (d *crashDevice) Close() error                                         { return nil }
func (d *crashDevice) Read(_ context.Context, view deploy.View) (deploy.Capture, error) {
	name := "running"
	d.reads++
	if view == deploy.Saved {
		name = "saved"
		d.savedReads++
	}
	text, err := os.ReadFile(filepath.Join(d.root, name))
	if err != nil {
		return deploy.Capture{}, err
	}
	return deploy.Capture{Source: config.Source{Text: string(text), Complete: true}, Metadata: d.before.Metadata()}, nil
}
func (d *crashDevice) Parse(_ context.Context, source config.Source, _ fm.Metadata) (*fm.Firewall, error) {
	f := d.before
	if source.Text == "after" {
		f = d.after
	} else if source.Text != "before" {
		return nil, errors.New("unknown synthetic device state")
	}
	data := f.Export()
	data.Raw = source.Text
	data.Metadata.SourceDigest = ""
	return fm.Seal(data)
}
func writeCrashState(root, name, value string) error {
	f, err := os.OpenFile(filepath.Join(root, name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.WriteString(value)
	syncErr := f.Sync()
	return errors.Join(writeErr, syncErr, f.Close())
}
func (d *crashDevice) Execute(ctx context.Context, commands []string, receipt deploy.ReceiptFunc) (deploy.Outcome, error) {
	d.writes++
	if d.point == "" {
		return deploy.Outcome{}, errors.New("recovery attempted configuration write")
	}
	if d.point == "write-intent" {
		os.Exit(86)
	}
	if err := writeCrashState(d.root, "running", "after"); err != nil {
		return deploy.Outcome{}, err
	}
	if d.point == "first-write" {
		os.Exit(86)
	}
	for i := range commands {
		if err := receipt(ctx, deploy.Receipt{Index: i, Written: true, Confirmed: true}); err != nil {
			return deploy.Outcome{}, err
		}
	}
	return deploy.Outcome{Complete: true}, nil
}
func (d *crashDevice) Save(ctx context.Context, receipt deploy.ReceiptFunc) (deploy.Outcome, error) {
	d.saves++
	if d.point == "" {
		return deploy.Outcome{}, errors.New("recovery attempted save")
	}
	if err := writeCrashState(d.root, "saved", "after"); err != nil {
		return deploy.Outcome{}, err
	}
	if d.point == "save-written" {
		os.Exit(86)
	}
	if err := receipt(ctx, deploy.Receipt{Index: 0, Written: true, Confirmed: true, Durable: true}); err != nil {
		return deploy.Outcome{}, err
	}
	if d.point == "save-receipt" {
		os.Exit(86)
	}
	return deploy.Outcome{Complete: true, Durable: true}, nil
}

type crashRepository struct {
	*snapshot.Store
	point string
}

func (r crashRepository) Publish(ctx context.Context, f *fm.Firewall, opts snapshot.PublishOptions) (snapshot.PublishResult, error) {
	result, err := r.Store.Publish(ctx, f, opts)
	if err == nil && r.point == "published" && opts.PublicationID == "operation:complete" {
		os.Exit(86)
	}
	return result, err
}

func crashFixture(t *testing.T, root, point string) (deploy.Engine, *crashDevice, *plan.Plan, *snapshot.Store) {
	t.Helper()
	before, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}})
	if err != nil {
		t.Fatal(err)
	}
	src, _ := flow.PrefixRange(netip.MustParsePrefix("192.0.2.1/32"))
	dst, _ := flow.PrefixRange(netip.MustParsePrefix("198.51.100.1/32"))
	traffic, err := flow.NewTraffic(8, flow.Box{Source: src, Destination: dst, Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{High: 65535}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := (plan.Planner{Renderer: testRenderer{}}).Plan(context.Background(), before, []policy.Request{{Traffic: traffic}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := snapshot.Open(filepath.Join(root, "store"))
	if err != nil {
		t.Fatal(err)
	}
	journal, err := deploy.OpenJournal(filepath.Join(root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	d := &crashDevice{root: root, point: point, before: before, after: p.After()}
	e := deploy.Engine{Store: crashRepository{Store: store, point: point}, Journal: journal, Sessions: d, Parser: d, Authorizer: deploy.AuthorizeFunc(func(context.Context, deploy.Authorization) error { return nil })}
	return e, d, p, store
}

func TestDeploymentSurvivesProcessExitWithoutReplayingWrites(t *testing.T) {
	for _, point := range []string{"write-intent", "first-write", "save-written", "save-receipt", "published"} {
		t.Run(point, func(t *testing.T) {
			root := t.TempDir()
			engine, device, p, store := crashFixture(t, root, "")
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			baseline, err := store.Publish(ctx, device.before, snapshot.PublishOptions{PublicationID: "baseline"})
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"running", "saved"} {
				if err := writeCrashState(root, name, "before"); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDeploymentCrashHelper$")
			command.Env = append(os.Environ(), "FIREMON_DEPLOY_CRASH_ROOT="+root, "FIREMON_DEPLOY_CRASH_POINT="+point)
			output, err := command.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 86 {
				t.Fatalf("helper did not reach crash point: %v %s", err, output)
			}
			// OS operation locks must have been released by process exit, while the
			// journal intent and any unfinalized reservation must remain durable.
			lease, err := engine.Journal.Acquire(ctx, "operation")
			if err != nil {
				t.Fatal(err)
			}
			record, err := lease.Load(ctx)
			closeErr := lease.Close()
			if err != nil || closeErr != nil || !record.WriteStarted {
				t.Fatal(record, err, closeErr)
			}
			if point == "save-receipt" && !record.Saved {
				t.Fatal("durable save receipt disappeared")
			}
			if point != "published" {
				if _, _, err := store.Current(ctx, "fw"); !errors.Is(err, snapshot.ErrUnavailable) {
					t.Fatal("crashed operation exposed a current graph", err)
				}
			}
			// A saved receipt is historical evidence. Recovery must notice a later
			// external change to persistent state instead of trusting that receipt.
			if point == "save-receipt" {
				if err := writeCrashState(root, "saved", "before"); err != nil {
					t.Fatal(err)
				}
			}
			result, err := engine.Recover(ctx, "operation", p)
			if point == "first-write" || point == "save-receipt" {
				if !errors.Is(err, deploy.ErrUncertain) {
					t.Fatal("unsaved state was published", result, err)
				}
				manifest, readErr := store.Manifest(ctx)
				if readErr != nil || manifest.Reservations["fw"].Token != "operation" || manifest.Devices["fw"].Complete {
					t.Fatal(manifest, readErr)
				}
				if err := writeCrashState(root, "saved", "after"); err != nil {
					t.Fatal(err)
				}
				result, err = engine.Recover(ctx, "operation", p)
			}
			want := deploy.Published
			if point == "write-intent" {
				want = deploy.Aborted
			}
			if err != nil || result.Phase != want || !result.Recovered {
				t.Fatal(result, err)
			}
			if device.writes != 0 || device.saves != 0 {
				t.Fatal("uncertain writes replayed", device.writes, device.saves)
			}
			if point != "published" && device.savedReads == 0 {
				t.Fatal("recovery omitted persistent-state read")
			}
			current, head, err := store.Current(ctx, "fw")
			if err != nil {
				t.Fatal(err)
			}
			if point == "write-intent" {
				if head.Revision != baseline.Revision {
					t.Fatal("unchanged baseline was replaced")
				}
			} else if _, err := p.Verify(ctx, current); err != nil {
				t.Fatal(err)
			}
			reads := device.reads
			again, err := engine.Recover(ctx, "operation", p)
			if err != nil || again.Phase != want || device.reads != reads {
				t.Fatal("finalized recovery was not idempotent", again, err)
			}
		})
	}
}

func TestDeploymentCrashHelper(t *testing.T) {
	root, point := os.Getenv("FIREMON_DEPLOY_CRASH_ROOT"), os.Getenv("FIREMON_DEPLOY_CRASH_POINT")
	if root == "" || point == "" {
		t.Skip("subprocess helper")
	}
	engine, _, p, store := crashFixture(t, root, point)
	_, head, err := store.Current(context.Background(), "fw")
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Apply(context.Background(), "operation", head.Revision, p)
	t.Fatal(fmt.Sprintf("crash point %s was not reached", point), err)
}

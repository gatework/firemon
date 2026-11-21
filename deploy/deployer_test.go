package deploy_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gatework/netops/apply"
	"github.com/gatework/netops/change"
	ndevice "github.com/gatework/netops/device"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/traffic"
	"github.com/gatework/firemon/vendors/hillstone"
)

var now = time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)

// device is an in-memory StoneOS: configuration lines written in
// configuration mode are appended to the running configuration.
type device struct {
	text   string
	writes []string
	failOn string
	extra  string // appended by the device after the last write
}

func (d *device) Read(context.Context) (*firemon.Config, error) {
	return hillstone.New(hillstone.Options{}).Parse(d.text) //nolint:contextcheck // synthetic configuration is already in memory
}

func (d *device) Write(_ context.Context, cmd change.Command) error {
	command := cmd.Text
	if command == d.failOn {
		return errors.New("device rejected command")
	}
	d.writes = append(d.writes, command)
	if command == "exit" && d.extra != "" && len(d.writes) > 1 {
		defer func() { d.text += d.extra; d.extra = "" }()
	}
	if command != "configure" {
		d.text += command + "\n" // the final exit leaves configuration mode and is ignored by the parser
	}
	return nil
}

func (d *device) open(ctx context.Context, run func(context.Context, apply.Session[*firemon.Config]) error) (error, error) {
	return run(ctx, d), nil
}

// journal keeps every execution record in memory.
type journal struct{ records []apply.Record }

func (j *journal) Execution(string, string) apply.Journal { return j }

func (j *journal) Write(_ context.Context, r apply.Record) error {
	j.records = append(j.records, r)
	return nil
}

func fixture(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "vendors", "hillstone", "testdata", "basic.conf"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func planFor(t *testing.T, text string) (*design.Plan, []string) {
	t.Helper()
	cfg, err := hillstone.New(hillstone.Options{}).Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	in := design.Intent{Name: "req"}
	in.Src, _ = traffic.ParseAddressSet("10.0.5.0/24")
	in.Dst, _ = traffic.ParseAddressSet("172.16.0.40")
	in.Service, _ = traffic.ParseServiceSet("tcp/8443")
	p, err := design.New(fw, design.Options{Now: func() time.Time { return now }}).Plan(in)
	if err != nil {
		t.Fatal(err)
	}
	script, err := hillstone.Renderer{}.Render(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, hillstone.DeployCommands(script)
}

func TestDeployer_Deploy(t *testing.T) {
	t.Parallel()
	text := fixture(t)
	p, commands := planFor(t, text)
	dev := &device{text: text}
	j := &journal{}
	d := deploy.New(dev.open, deploy.Options{Writer: fixed(commands), Journal: j, Now: func() time.Time { return now }})
	receipt, err := d.Deploy(t.Context(), deploy.Request{Plan: p, Device: ndevice.Device{ID: "lab", Platform: "hillstone"}})
	if err != nil {
		t.Fatalf("deploy: %v (state %+v)", err, receipt.Record)
	}
	if receipt.Record.Status != apply.StatusVerified || len(dev.writes) != len(commands) {
		t.Fatalf("status %s, %d writes of %d", receipt.Record.Status, len(dev.writes), len(commands))
	}
}

func TestDeployer_PersistsCloseFailure(t *testing.T) {
	t.Parallel()
	text := fixture(t)
	p, commands := planFor(t, text)
	dev := &device{text: text}
	j := &journal{}
	closeErr := errors.New("session close failed")
	open := func(ctx context.Context, run func(context.Context, apply.Session[*firemon.Config]) error) (error, error) {
		return run(ctx, dev), closeErr
	}
	d := deploy.New(open, deploy.Options{Writer: fixed(commands), Journal: j, Now: func() time.Time { return now }})
	receipt, err := d.Deploy(t.Context(), deploy.Request{Plan: p, Device: ndevice.Device{ID: "lab", Platform: "hillstone"}})
	if !errors.Is(err, closeErr) || !receipt.ReportUnconfirmed || receipt.Record.Status != apply.StatusUncertain {
		t.Fatalf("receipt = %+v, error = %v", receipt, err)
	}
	last := j.records[len(j.records)-1]
	if last.Status != apply.StatusUncertain || last.Stage != apply.StageClose {
		t.Fatalf("persisted status = %s, stage = %s", last.Status, last.Stage)
	}
}

func TestDeployer_RefusesDrift(t *testing.T) {
	t.Parallel()
	text := fixture(t)
	p, commands := planFor(t, text)
	dev := &device{text: text + "address \"late\"\n  ip 192.0.2.1/32\nexit\n"}
	d := deploy.New(dev.open, deploy.Options{Writer: fixed(commands), Journal: &journal{}, Now: func() time.Time { return now }})
	_, err := d.Deploy(t.Context(), deploy.Request{Plan: p})
	if !errors.Is(err, deploy.ErrDrift) || len(dev.writes) != 0 {
		t.Fatalf("err %v writes %d", err, len(dev.writes))
	}
}

func TestDeployer_StopsOnRejectedCommand(t *testing.T) {
	t.Parallel()
	text := fixture(t)
	p, commands := planFor(t, text)
	dev := &device{text: text, failOn: commands[2]}
	d := deploy.New(dev.open, deploy.Options{Writer: fixed(commands), Journal: &journal{}, Now: func() time.Time { return now }})
	receipt, err := d.Deploy(t.Context(), deploy.Request{Plan: p})
	if err == nil || receipt.Record.Status == apply.StatusVerified || len(dev.writes) != 2 {
		t.Fatalf("err %v status %s writes %d", err, receipt.Record.Status, len(dev.writes))
	}
}

// TestD7_UnexpectedReadbackFails covers a device that changes more than
// the plan: the readback must be the baseline plus the plan exactly.
func TestD7_UnexpectedReadbackFails(t *testing.T) {
	t.Parallel()
	text := fixture(t)
	p, commands := planFor(t, text)
	dev := &device{text: text, extra: "address \"device-added\"\n  ip 192.0.2.77/32\nexit\n"}
	d := deploy.New(dev.open, deploy.Options{Writer: fixed(commands), Journal: &journal{}, Now: func() time.Time { return now }})
	_, err := d.Deploy(t.Context(), deploy.Request{Plan: p})
	if !errors.Is(err, deploy.ErrUnexpectedReadback) {
		t.Fatalf("got %v", err)
	}
}

func fixed(commands []string) deploy.Writer {
	return deploy.WriterFunc(func(*design.Plan) ([]string, error) { return commands, nil })
}

package operations_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/device"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
)

// nativeDevice applies only the synthetic PAN set commands used by this test.
// Readback is parsed independently through the production native parser.
type nativeDevice struct {
	running, saved, token                  string
	opens, closes, active, executes, saves int
	begins, ends                           int
}

type nativeSession struct {
	device *nativeDevice
	closed bool
}

func (d *nativeDevice) Open(ctx context.Context, device string) (deploy.Session, error) {
	if ctx.Err() != nil || device != "pan" || d.active != 0 {
		return nil, errors.New("session overlap or invalid request")
	}
	d.opens++
	d.active++
	return &nativeSession{device: d}, nil
}
func (s *nativeSession) Read(ctx context.Context, view device.View) (device.Capture, error) {
	raw := s.device.running
	if view == device.Saved {
		raw = s.device.saved
	}
	return device.Capture{Source: config.Source{Text: raw, Complete: true}, Metadata: fm.Metadata{Device: "pan", Vendor: "paloalto"}}, ctx.Err()
}
func (s *nativeSession) BeginConfiguration(ctx context.Context, token string) error {
	if token == "" || s.device.token != "" {
		return errors.New("candidate ownership conflict")
	}
	s.device.token = token
	s.device.begins++
	return ctx.Err()
}
func (s *nativeSession) EndConfiguration(ctx context.Context, token string) error {
	if token == "" || token != s.device.token {
		return errors.New("candidate ownership mismatch")
	}
	s.device.token = ""
	s.device.ends++
	return ctx.Err()
}
func (s *nativeSession) Execute(ctx context.Context, commands []string, receipt deploy.ReceiptFunc) (deploy.Outcome, error) {
	if s.device.token == "" {
		return deploy.Outcome{}, errors.New("write without candidate ownership")
	}
	s.device.executes++
	for i, command := range commands {
		if strings.HasPrefix(command, "set ") {
			s.device.running += command + "\n"
		}
		if err := receipt(ctx, deploy.Receipt{Index: i, Written: true, Confirmed: true}); err != nil {
			return deploy.Outcome{}, err
		}
	}
	return deploy.Outcome{Complete: true}, nil
}
func (s *nativeSession) Save(ctx context.Context, receipt deploy.ReceiptFunc) (deploy.Outcome, error) {
	s.device.saved = s.device.running
	s.device.saves++
	if err := receipt(ctx, deploy.Receipt{Index: 0, Written: true, Confirmed: true, Durable: true}); err != nil {
		return deploy.Outcome{}, err
	}
	return deploy.Outcome{Complete: true, Durable: true}, nil
}
func (s *nativeSession) Close() error {
	if s.closed {
		return errors.New("session closed twice")
	}
	s.closed = true
	s.device.closes++
	s.device.active--
	return nil
}

func TestRuntimeCollectDesignApplyAndRecoveryUseOneNativeComposition(t *testing.T) {
	ctx := context.Background()
	store, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	journal, err := deploy.OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	device := &nativeDevice{running: panBase, saved: panBase}
	authorizations := 0
	var authorization deploy.Authorization
	runtime, err := operations.New(operations.Options{Store: store, Journal: journal, Sessions: device, Authorizer: deploy.AuthorizeFunc(func(_ context.Context, a deploy.Authorization) error {
		authorizations++
		authorization = a
		return nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	collected, err := runtime.Collect(ctx, operations.CollectRequest{Device: "pan", PublicationID: "first-capture"})
	if err != nil || !collected.Complete || device.begins != 0 {
		t.Fatal("read-only collection acquired a candidate or failed", collected, err)
	}
	designed, err := runtime.Design(ctx, "pan", []policy.Request{{Traffic: requestTraffic(t, "192.0.2.10/32", "198.51.100.10/32", 1024), FromZone: "inside", ToZone: "outside"}})
	if err != nil || designed.Revision != collected.Revision || len(designed.Plan.Commands()) == 0 {
		t.Fatal("design failed", err)
	}
	applied, err := runtime.Apply(ctx, "approved-operation", designed.Revision, designed.Plan)
	if err != nil || applied.Phase != deploy.Published {
		t.Fatal("native apply/readback failed", applied, err)
	}
	if authorizations != 1 || authorization.Device != "pan" || authorization.BaselineRevision != collected.Revision || authorization.PlanDigest != designed.Plan.Digest() {
		t.Fatal("host authorization lost exact-plan binding", authorization)
	}
	if device.opens != 3 || device.closes != 3 || device.active != 0 || device.executes != 1 || device.saves != 1 || device.begins != 1 || device.ends != 1 {
		t.Fatal("session, candidate or persistence ownership lost", device)
	}
	fw, head, err := store.Current(ctx, "pan")
	if err != nil || head.Revision != applied.Revision || fw.SemanticDigest() != designed.Plan.After().SemanticDigest() || fw.Export().Raw != device.saved {
		t.Fatal("published snapshot does not match independent native readback", head, err)
	}
	if _, err := runtime.Apply(ctx, "approved-operation", designed.Revision, designed.Plan); err != nil {
		t.Fatal("idempotent apply", err)
	}
	if result, err := runtime.Recover(ctx, "approved-operation", designed.Plan); err != nil || !result.Recovered || result.Revision != applied.Revision {
		t.Fatal("completed recovery", result, err)
	}
	if device.opens != 3 || device.executes != 1 || device.saves != 1 {
		t.Fatal("retry/recovery repeated device activity", device)
	}
}

func TestRuntimeRequiresExplicitHostDependencies(t *testing.T) {
	if _, err := operations.New(operations.Options{}); !errors.Is(err, operations.ErrInvalid) {
		t.Fatal("missing host dependencies accepted", err)
	}
}

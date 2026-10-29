package deploy_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/gatework/firemon/deploy"
)

type guardedFactory struct {
	base     deploy.Factory
	events   *[]string
	beginErr error
	endErr   error
	readErr  error
}

func (f guardedFactory) Open(ctx context.Context, id string) (deploy.Session, error) {
	s, err := f.base.Open(ctx, id)
	return &guardedSession{Session: s, events: f.events, beginErr: f.beginErr, endErr: f.endErr, readErr: f.readErr}, err
}

type guardedSession struct {
	deploy.Session
	events   *[]string
	beginErr error
	endErr   error
	readErr  error
}

func (s *guardedSession) BeginConfiguration(_ context.Context, token string) error {
	*s.events = append(*s.events, "begin:"+token)
	return s.beginErr
}
func (s *guardedSession) EndConfiguration(_ context.Context, token string) error {
	*s.events = append(*s.events, "end:"+token)
	return s.endErr
}
func (s *guardedSession) Read(ctx context.Context, v deploy.View) (deploy.Capture, error) {
	*s.events = append(*s.events, "read")
	if s.readErr != nil {
		return deploy.Capture{}, s.readErr
	}
	return s.Session.Read(ctx, v)
}

func TestDeniedAuthorizationCannotAcquireConfigurationLock(t *testing.T) {
	for _, failRead := range []bool{false, true} {
		t.Run(map[bool]string{false: "readable", true: "capture-fails"}[failRead], func(t *testing.T) {
			f := newFixture(t)
			var events []string
			factory := guardedFactory{base: f.device, events: &events}
			if failRead {
				factory.readErr = errors.New("capture interrupted")
			}
			f.engine.Sessions = factory
			denied := errors.New("operation denied")
			f.engine.Authorizer = deploy.AuthorizeFunc(func(_ context.Context, a deploy.Authorization) error {
				events = append(events, "authorize")
				if a.Operation != "op" || a.Device != "fw" || a.BaselineRevision != f.expected || a.PlanDigest != f.plan.Digest() {
					t.Fatal("authorization is not bound to the exact operation", a)
				}
				return denied
			})
			if _, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan); !errors.Is(err, denied) {
				t.Fatalf("unauthorized request reached device work: events=%v err=%v", events, err)
			}
			if len(events) != 1 || events[0] != "authorize" || f.device.opens != 0 {
				t.Fatalf("denial acquired device resources: events=%v opens=%d", events, f.device.opens)
			}
			if _, head, err := f.store.Current(context.Background(), "fw"); err != nil || head.Revision != f.expected {
				t.Fatal("denial changed or reserved the baseline", head, err)
			}
			r := f.record(t)
			if r.Phase != deploy.Aborted || r.ConfigurationToken != "" || r.WriteStarted {
				t.Fatal("denial left device ownership pending", r)
			}
		})
	}
}
func TestConfigurationGuardPrecedesFreshBaseline(t *testing.T) {
	f := newFixture(t)
	var events []string
	blocked := errors.New("device configuration locked")
	f.engine.Sessions = guardedFactory{base: f.device, events: &events, beginErr: blocked}
	_, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan)
	if !errors.Is(err, blocked) || len(events) != 1 || f.device.executes != 0 {
		t.Fatalf("lock must precede read/write: events=%v executes=%d err=%v", events, f.device.executes, err)
	}
}

func TestConfigurationReleaseFailureRemainsRecoverable(t *testing.T) {
	f := newFixture(t)
	var events []string
	fault := errors.New("lock release not confirmed")
	f.engine.Sessions = guardedFactory{base: f.device, events: &events, endErr: fault}
	if _, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan); !errors.Is(err, deploy.ErrUncertain) || !errors.Is(err, fault) {
		t.Fatal(err)
	}
	r := f.record(t)
	if r.ConfigurationToken == "" || r.ConfigurationReleased || !r.Saved || r.Phase == deploy.Published {
		t.Fatal(r)
	}
	if len(events) != 3 || !strings.HasPrefix(events[0], "begin:") || events[1] != "read" || events[2] != "end:"+r.ConfigurationToken {
		t.Fatal(events)
	}
	f.engine.Sessions = guardedFactory{base: f.device, events: &events}
	result, err := f.engine.Recover(context.Background(), "op", f.plan)
	if err != nil || result.Phase != deploy.Published || !f.record(t).ConfigurationReleased {
		t.Fatal(result, err)
	}
	if events[3] != "end:"+r.ConfigurationToken || events[4] != "read" || f.device.executes != 1 || f.device.saves != 1 {
		t.Fatal(events, f.device)
	}
}

func TestConfigurationTokenSurvivesCanceledAcquire(t *testing.T) {
	f := newFixture(t)
	var events []string
	f.engine.Sessions = guardedFactory{base: f.device, events: &events, beginErr: context.Canceled}
	if _, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	r := f.record(t)
	if r.ConfigurationToken == "" || r.ConfigurationReleased || r.WriteStarted {
		t.Fatal(r)
	}
	f.engine.Sessions = guardedFactory{base: f.device, events: &events}
	result, err := f.engine.Recover(context.Background(), "op", f.plan)
	if err != nil || result.Phase != deploy.Aborted || f.device.executes != 0 || f.device.saves != 0 {
		t.Fatal(result, err)
	}
}

type captureMetadataFactory struct {
	base  deploy.Factory
	alter func(*deploy.Capture)
}

func (f captureMetadataFactory) Open(ctx context.Context, id string) (deploy.Session, error) {
	s, err := f.base.Open(ctx, id)
	return &captureMetadataSession{Session: s, alter: f.alter}, err
}

type captureMetadataSession struct {
	deploy.Session
	alter func(*deploy.Capture)
}

func (s *captureMetadataSession) Read(ctx context.Context, view deploy.View) (deploy.Capture, error) {
	capture, err := s.Session.Read(ctx, view)
	if err == nil {
		s.alter(&capture)
	}
	return capture, err
}
func TestParserCannotReplaceFreshCaptureMetadataBeforeExecute(t *testing.T) {
	for _, field := range []string{"software", "capture-time", "context"} {
		t.Run(field, func(t *testing.T) {
			f := newFixture(t)
			f.engine.Sessions = captureMetadataFactory{base: f.device, alter: func(c *deploy.Capture) {
				switch field {
				case "software":
					c.Metadata.Software = "changed-firmware"
				case "capture-time":
					c.Metadata.CapturedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
				case "context":
					c.Metadata.Context = "other"
				}
			}}
			_, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan)
			if !errors.Is(err, deploy.ErrInvalid) || f.device.executes != 0 || f.device.saves != 0 {
				t.Fatalf("metadata substitution reached writes: executes=%d saves=%d err=%v", f.device.executes, f.device.saves, err)
			}
		})
	}
}

type interruptedCaptureFactory struct {
	base   deploy.Factory
	opens  int
	failAt int
	cancel context.CancelFunc
}

func (f *interruptedCaptureFactory) Open(ctx context.Context, id string) (deploy.Session, error) {
	s, err := f.base.Open(ctx, id)
	if err != nil {
		return s, err
	}
	f.opens++
	if f.opens == f.failAt {
		return interruptedCaptureSession{Session: s, cancel: f.cancel}, nil
	}
	return s, nil
}

type interruptedCaptureSession struct {
	deploy.Session
	cancel context.CancelFunc
}

const partialConfiguration = "set security policies from-zone inside to-zone outside\n"

func (s interruptedCaptureSession) Read(ctx context.Context, view deploy.View) (deploy.Capture, error) {
	capture, err := s.Session.Read(ctx, view)
	if err != nil {
		return capture, err
	}
	capture.Source.Text, capture.Source.Complete = partialConfiguration, false
	if s.cancel != nil {
		s.cancel()
		return capture, context.Canceled
	}
	return capture, io.ErrUnexpectedEOF
}

func TestInterruptedRunningCaptureIsArchivedWithoutWriteReplay(t *testing.T) {
	for _, phase := range []struct {
		name   string
		failAt int
		writes int
	}{{"baseline", 1, 0}, {"readback", 2, 1}} {
		for _, canceled := range []bool{false, true} {
			t.Run(phase.name+"/"+map[bool]string{false: "eof", true: "cancel"}[canceled], func(t *testing.T) {
				f := newFixture(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				factory := &interruptedCaptureFactory{base: f.device, failAt: phase.failAt}
				cause := io.ErrUnexpectedEOF
				if canceled {
					factory.cancel, cause = cancel, context.Canceled
				}
				f.engine.Sessions = factory
				if _, err := f.engine.Apply(ctx, "op", f.expected, f.plan); !errors.Is(err, deploy.ErrUncertain) || !errors.Is(err, cause) {
					t.Fatal("interrupted capture lost the failure", err)
				}
				m, err := f.store.Manifest(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				head := m.Devices["fw"]
				if head.Revision == f.expected || head.Complete || m.Reservations["fw"].Token != "op" {
					t.Fatal("partial running evidence was not published as uncertain", m)
				}
				observed, err := f.store.Load(context.Background(), head.Revision)
				if err != nil || observed.Export().Raw != partialConfiguration || observed.Complete() {
					t.Fatal("partial capture was not retained", err)
				}
				if _, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan); !errors.Is(err, deploy.ErrPending) || factory.opens != phase.failAt {
					t.Fatal("retry reconnected or replayed an uncertain operation", err)
				}
				f.engine.Sessions = f.device
				result, err := f.engine.Recover(context.Background(), "op", f.plan)
				want := deploy.Aborted
				if phase.writes != 0 {
					want = deploy.Published
				}
				if err != nil || result.Phase != want || f.device.executes != phase.writes || f.device.saves != phase.writes {
					t.Fatal("fresh recovery failed or replayed writes", result, err)
				}
			})
		}
	}
}

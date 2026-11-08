package deploy_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/device"
	"github.com/gatework/firemon/snapshot"
)

type cancelSavedFactory struct {
	deploy.Factory
	cancel context.CancelFunc
}

func (f cancelSavedFactory) Open(ctx context.Context, id string) (deploy.Session, error) {
	s, err := f.Factory.Open(ctx, id)
	if err != nil {
		return s, err
	}
	return cancelSavedSession{Session: s, cancel: f.cancel}, nil
}

type cancelSavedSession struct {
	deploy.Session
	cancel context.CancelFunc
}

func (s cancelSavedSession) Read(ctx context.Context, view device.View) (device.Capture, error) {
	c, err := s.Session.Read(ctx, view)
	if view == device.Saved {
		s.cancel()
		return c, context.Canceled
	}
	return c, err
}

type finalizationKey struct{}
type observationStore struct {
	deploy.Repository
	t          *testing.T
	publishErr error
	archives   int
}

func (s *observationStore) Archive(ctx context.Context, fw *fm.Firewall) (string, error) {
	s.t.Helper()
	deadline, ok := ctx.Deadline()
	if ctx.Err() != nil || !ok || time.Until(deadline) > 5*time.Second || ctx.Value(finalizationKey{}) != "request" {
		s.t.Fatalf("observation did not retain bounded independent context: %v %v", ctx.Err(), deadline)
	}
	s.archives++
	return s.Repository.Archive(ctx, fw)
}
func (s *observationStore) Publish(ctx context.Context, fw *fm.Firewall, options snapshot.PublishOptions) (snapshot.PublishResult, error) {
	if !options.KeepReservation || !options.Live || fw.Complete() {
		s.t.Fatal("observation lost uncertainty or ownership")
	}
	if s.publishErr != nil {
		return snapshot.PublishResult{}, s.publishErr
	}
	return s.Repository.Publish(ctx, fw, options)
}

func TestCanceledSavedReadFinalizesObservedRunningEvidence(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		baseline, publicationFailure bool
	}{
		{"applied", false, false}, {"baseline", true, false}, {"publication failure", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.device.applyErr = errors.New("lost response")
			if _, err := f.engine.Apply(t.Context(), "op", f.expected, f.plan); !errors.Is(err, deploy.ErrUncertain) {
				t.Fatal(err)
			}
			if tc.baseline {
				f.device.running = f.device.before
			}
			observedRaw := f.device.running.SemanticDigest()
			ctx, cancel := context.WithCancel(context.WithValue(t.Context(), finalizationKey{}, "request"))
			defer cancel()
			store := &observationStore{Repository: f.store, t: t}
			if tc.publicationFailure {
				store.publishErr = errors.New("publication unavailable")
			}
			f.engine.Store = store
			f.engine.Sessions = cancelSavedFactory{Factory: f.device, cancel: cancel}
			_, err := f.engine.Recover(ctx, "op", f.plan)
			if !errors.Is(err, context.Canceled) || !errors.Is(err, deploy.ErrUncertain) || store.archives != 1 {
				t.Fatalf("lost failure or observation: %v archives=%d", err, store.archives)
			}
			if store.publishErr != nil && !errors.Is(err, store.publishErr) {
				t.Fatalf("lost persistence failure: %v", err)
			}
			r := f.record(t)
			archived, err := f.store.Load(t.Context(), r.ObservedRevision)
			if err != nil || archived.Raw() != observedRaw || archived.Complete() {
				t.Fatalf("running evidence not retained: %v", err)
			}
			m, err := f.store.Manifest(t.Context())
			if err != nil || m.Reservations["fw"].Token != "op" {
				t.Fatalf("lost reservation: %v", err)
			}
			if !tc.publicationFailure && (m.Devices["fw"].Complete || m.Devices["fw"].Revision != r.ObservedRevision) {
				t.Fatal("uncertain observation did not advance head")
			}
			if f.device.executes != 1 || f.device.saves != 0 {
				t.Fatal("recovery replayed device writes")
			}
		})
	}
}

func TestAbortedApplyReturnsConfirmedTerminalWithoutRetry(t *testing.T) {
	f := newFixture(t)
	denied := errors.New("authorization denied")
	f.engine.Authorizer = deploy.AuthorizeFunc(func(context.Context, deploy.Authorization) error { return denied })
	r, err := f.engine.Apply(t.Context(), "op", f.expected, f.plan)
	if !r.Terminal() || r.Phase != deploy.Aborted || !errors.Is(err, denied) {
		t.Fatalf("lost confirmed abortion or cause: %+v %v", r, err)
	}
	r, err = f.engine.Apply(t.Context(), "op", f.expected, f.plan)
	if !r.Terminal() || r.Phase != deploy.Aborted || err != nil || f.device.opens != 0 {
		t.Fatalf("terminal retry requires recovery or opens device: %+v %v", r, err)
	}
}

type uncertainReservationStore struct {
	deploy.Repository
	err error
}

func (s uncertainReservationStore) Reserve(ctx context.Context, device, expected, token string) error {
	if err := s.Repository.Reserve(ctx, device, expected, token); err != nil {
		return err
	}
	return s.err
}

func TestReservationDurabilityFailureCannotBecomeTerminalAbortion(t *testing.T) {
	f := newFixture(t)
	fault := errors.New("reservation directory sync failed")
	f.engine.Store = uncertainReservationStore{Repository: f.store, err: fault}
	r, err := f.engine.Apply(t.Context(), "op", f.expected, f.plan)
	if r.Terminal() || !errors.Is(err, fault) || !errors.Is(err, deploy.ErrUncertain) || f.record(t).Phase == deploy.Aborted {
		t.Fatalf("uncertain reservation became terminal: %+v %v", r, err)
	}
	if _, _, err := f.store.Current(t.Context(), "fw"); !errors.Is(err, snapshot.ErrUnavailable) {
		t.Fatal("reservation not retained", err)
	}
	if _, err := f.engine.Apply(t.Context(), "op", f.expected, f.plan); !errors.Is(err, deploy.ErrPending) || f.device.opens != 0 {
		t.Fatal("retry opened device", err)
	}
	r, err = f.engine.Recover(t.Context(), "op", f.plan)
	if err != nil || !r.Terminal() || r.Phase != deploy.Aborted || f.device.executes != 0 || f.device.saves != 0 {
		t.Fatalf("independent recovery failed: %+v %v", r, err)
	}
	if _, _, err := f.store.Current(t.Context(), "fw"); err != nil {
		t.Fatal("recovery stranded reservation", err)
	}
}

type concurrentPublicationStore struct {
	deploy.Repository
	next *fm.Firewall
}

func (s concurrentPublicationStore) Reserve(ctx context.Context, device, expected, token string) error {
	if _, err := s.Repository.Publish(ctx, s.next, snapshot.PublishOptions{Expected: expected, PublicationID: "concurrent"}); err != nil {
		return err
	}
	return s.Repository.Reserve(ctx, device, expected, token)
}

func TestRecoveryAfterConcurrentPublicationAbortsBeforeDeviceWork(t *testing.T) {
	f := newFixture(t)
	f.engine.Store = concurrentPublicationStore{Repository: f.store, next: f.plan.After()}
	r, err := f.engine.Apply(t.Context(), "op", f.expected, f.plan)
	if !errors.Is(err, snapshot.ErrConflict) || r.Terminal() || f.device.opens != 0 {
		t.Fatalf("reservation conflict lost or opened device: %+v %v opens=%d", r, err, f.device.opens)
	}
	m, err := f.store.Manifest(t.Context())
	if err != nil || len(m.Reservations) != 0 || m.Devices["fw"].Revision == f.expected {
		t.Fatalf("concurrent publication did not advance unreserved head: %+v %v", m, err)
	}
	for range 2 {
		r, err = f.engine.Recover(t.Context(), "op", f.plan)
		if err != nil || !r.Terminal() || r.Phase != deploy.Aborted || !r.Recovered || r.Revision != "" || f.device.opens != 0 {
			t.Fatalf("pre-device conflict did not finish idempotently: %+v %v opens=%d", r, err, f.device.opens)
		}
	}
	if f.record(t).Phase != deploy.Aborted {
		t.Fatal("terminal result was not durable")
	}
	_, head, err := f.store.Current(t.Context(), "fw")
	if err != nil || !reflect.DeepEqual(head, m.Devices["fw"]) {
		t.Fatalf("recovery changed concurrent publication: %+v %v", head, err)
	}
}

type closeFailureFactory struct {
	deploy.Factory
	failAt, opens, closes int
	err                   error
}

func (f *closeFailureFactory) Open(ctx context.Context, id string) (deploy.Session, error) {
	s, err := f.Factory.Open(ctx, id)
	if err != nil {
		return s, err
	}
	f.opens++
	if f.opens == f.failAt {
		return closeFailureSession{Session: s, owner: f}, nil
	}
	return s, nil
}

type closeFailureSession struct {
	deploy.Session
	owner *closeFailureFactory
}

func (s closeFailureSession) Close() error {
	s.owner.closes++
	return errors.Join(s.Session.Close(), s.owner.err)
}

func TestDeploymentCloseFailureRetainsOnlyConfirmedTerminal(t *testing.T) {
	for _, tc := range []struct {
		name     string
		failAt   int
		terminal bool
	}{
		{"before readback", 1, false}, {"after publication", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			factory := &closeFailureFactory{Factory: f.device, failAt: tc.failAt, err: errors.New("transport close failed")}
			f.engine.Sessions = factory
			r, err := f.engine.Apply(t.Context(), "op", f.expected, f.plan)
			if !errors.Is(err, factory.err) || r.Terminal() != tc.terminal || factory.closes != 1 {
				t.Fatalf("close failure lost or terminal invented: %+v %v closes=%d", r, err, factory.closes)
			}
			if tc.terminal {
				if r.Phase != deploy.Published || errors.Is(err, deploy.ErrUncertain) || f.record(t).Phase != deploy.Published {
					t.Fatal("confirmed publication needs recovery", r, err)
				}
			} else if !errors.Is(err, deploy.ErrUncertain) {
				t.Fatal("unverified readback claimed completion", err)
			}
		})
	}
}

func TestMissingReservationCannotEraseConfigurationIntent(t *testing.T) {
	f := newFixture(t)
	var events []string
	fault := errors.New("configuration acquisition response lost")
	f.engine.Sessions = guardedFactory{base: f.device, events: &events, beginErr: fault}
	result, err := f.engine.Apply(t.Context(), "op", f.expected, f.plan)
	before := f.record(t)
	if !errors.Is(err, fault) || result.Terminal() || before.ConfigurationToken == "" || before.ConfigurationReleased || before.WriteStarted {
		t.Fatalf("fixture: %+v err=%v record=%+v", result, err, before)
	}
	// Simulate loss of local ownership while device-side acquisition is unconfirmed.
	if err := f.store.ReleaseUnchanged(t.Context(), "fw", "op", f.expected); err != nil {
		t.Fatal(err)
	}
	result, err = f.engine.Recover(t.Context(), "op", f.plan)
	after := f.record(t)
	if !errors.Is(err, deploy.ErrPending) || result.Terminal() || after.Phase != before.Phase || after.Sequence != before.Sequence || after.ConfigurationReleased || after.ConfigurationToken != before.ConfigurationToken || f.device.opens != 1 || len(events) != 1 {
		t.Fatalf("lost reservation erased unconfirmed configuration intent: result=%+v err=%v before=%+v after=%+v events=%v", result, err, before, after, events)
	}
}

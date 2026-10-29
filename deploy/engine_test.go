package deploy_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/device"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
)

type testRenderer struct{}

func (testRenderer) Render(context.Context, *fm.Firewall, *fm.Firewall, []plan.Change) ([]string, error) {
	return []string{"enter", "change", "leave"}, nil
}

type fakeDevice struct {
	mu                                     sync.Mutex
	before, after, running, saved          *fm.Firewall
	executes, saves, opens, closed, active int
	applyErr, saveErr                      error
	badReadback, omitReceipts              bool
}
type fakeSession struct {
	d      *fakeDevice
	closed bool
}

func (*fakeSession) BeginConfiguration(context.Context, string) error { return nil }
func (*fakeSession) EndConfiguration(context.Context, string) error   { return nil }

func (d *fakeDevice) Open(_ context.Context, _ string) (deploy.Session, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.active != 0 {
		return nil, errors.New("prior session still owned")
	}
	d.active++
	d.opens++
	return &fakeSession{d: d}, nil
}
func (s *fakeSession) Read(_ context.Context, view device.View) (device.Capture, error) {
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	fw := s.d.running
	if view == device.Saved {
		fw = s.d.saved
	}
	return device.Capture{Source: config.Source{Text: fw.SemanticDigest(), Complete: true}, Metadata: fw.Metadata()}, nil
}
func (s *fakeSession) Execute(ctx context.Context, commands []string, receipt deploy.ReceiptFunc) (deploy.Outcome, error) {
	s.d.mu.Lock()
	s.d.executes++
	s.d.running = s.d.after
	if s.d.badReadback {
		d := s.d.after.Export()
		d.Rules[0].Log = fm.Known
		s.d.running, _ = fm.Seal(d)
	}
	err, omit := s.d.applyErr, s.d.omitReceipts
	s.d.mu.Unlock()
	if err != nil {
		return deploy.Outcome{}, err
	}
	if !omit {
		for i := range commands {
			if err := receipt(ctx, deploy.Receipt{Index: i, Written: true, Confirmed: true}); err != nil {
				return deploy.Outcome{}, err
			}
		}
	}
	return deploy.Outcome{Complete: true}, nil
}
func (s *fakeSession) Save(ctx context.Context, receipt deploy.ReceiptFunc) (deploy.Outcome, error) {
	s.d.mu.Lock()
	s.d.saves++
	s.d.saved = s.d.running
	err := s.d.saveErr
	s.d.mu.Unlock()
	if err != nil {
		return deploy.Outcome{}, err
	}
	if err := receipt(ctx, deploy.Receipt{Index: 0, Written: true, Confirmed: true, Durable: true}); err != nil {
		return deploy.Outcome{}, err
	}
	return deploy.Outcome{Complete: true, Durable: true}, nil
}
func (s *fakeSession) Close() error {
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.d.active--
		s.d.closed++
	}
	return nil
}
func (d *fakeDevice) Parse(_ context.Context, source config.Source, _ fm.Metadata) (*fm.Firewall, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, f := range []*fm.Firewall{d.before, d.after, d.running, d.saved} {
		if f.SemanticDigest() == source.Text {
			d := f.Export()
			d.Raw = source.Text
			d.Metadata.SourceDigest = ""
			return fm.Seal(d)
		}
	}
	return nil, errors.New("unknown fake capture")
}

type fixture struct {
	engine   configuredEngine
	device   *fakeDevice
	store    *snapshot.Store
	journal  *deploy.FileJournal
	plan     *plan.Plan
	expected string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	base, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}})
	if err != nil {
		t.Fatal(err)
	}
	src, _ := flow.PrefixRange(netip.MustParsePrefix("192.0.2.1/32"))
	dst, _ := flow.PrefixRange(netip.MustParsePrefix("198.51.100.1/32"))
	traffic, err := flow.NewTraffic(8, flow.Box{Source: src, Destination: dst, Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{High: 65535}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := (plan.Planner{Renderer: testRenderer{}}).Plan(context.Background(), base, []policy.Request{{Traffic: traffic}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, err := s.Publish(context.Background(), base, snapshot.PublishOptions{PublicationID: "base"})
	if err != nil {
		t.Fatal(err)
	}
	j, err := deploy.OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeDevice{before: base, after: p.After(), running: base, saved: base}
	e := configuredEngine{Options: deploy.Options{Store: s, Journal: j, Sessions: d, Parser: d, Authorizer: deploy.AuthorizeFunc(func(_ context.Context, a deploy.Authorization) error {
		if a.Device != "fw" || a.PlanDigest != p.Digest() || a.BaselineRevision != pub.Revision || a.Operation == "" {
			return errors.New("approval not bound to exact plan")
		}
		return nil
	})}, t: t}
	return fixture{e, d, s, j, p, pub.Revision}
}
func (f fixture) record(t *testing.T) deploy.Record {
	t.Helper()
	l, err := f.journal.Acquire(context.Background(), "op")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	r, err := l.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDeploymentPublishesOnlyAfterDurableSaveAndIndependentReadback(t *testing.T) {
	f := newFixture(t)
	r, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan)
	if err != nil {
		t.Fatal(err)
	}
	if r.Phase != deploy.Published || f.device.executes != 1 || f.device.saves != 1 || f.device.opens != 2 || f.device.active != 0 {
		t.Fatal("missing save/readback/session ownership", r, f.device)
	}
	fw, head, err := f.store.Current(context.Background(), "fw")
	if err != nil || head.Revision != r.Revision || fw.SemanticDigest() != f.plan.After().SemanticDigest() {
		t.Fatal("published wrong graph", err)
	}
	record := f.record(t)
	if !record.Saved || len(record.Receipts) != 4 || record.Phase != deploy.Published {
		t.Fatal("journal lacks durable evidence", record)
	}
	if _, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan); err != nil {
		t.Fatal("idempotent apply failed", err)
	}
	if f.device.executes != 1 {
		t.Fatal("idempotent retry replayed commands")
	}
}

func TestRecoveryBeforeWriteCannotPublishUnsavedExternalChange(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.store.Reserve(ctx, "fw", f.expected, "op"); err != nil {
		t.Fatal(err)
	}
	l, err := f.journal.Acquire(ctx, "op")
	if err != nil {
		t.Fatal(err)
	}
	_, err = l.Save(ctx, deploy.Record{ID: "op", Device: "fw", Vendor: "hillstone", BaselineRevision: f.expected, ExpectedRevision: f.expected, PlanDigest: f.plan.Digest(), Phase: deploy.Reserved})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	f.device.running = f.device.after
	if _, err := f.engine.Recover(ctx, "op", f.plan); !errors.Is(err, deploy.ErrUncertain) {
		t.Fatal("running-only external edit was published", err)
	}
	if f.device.executes != 0 || f.device.saves != 0 {
		t.Fatal("recovery wrote to the device")
	}
	m, err := f.store.Manifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if m.Reservations["fw"].Token != "op" {
		t.Fatal("uncertain reservation released")
	}
}

func TestPostWriteUncertaintyRequiresRecoveryAndNeverReplaysCommands(t *testing.T) {
	for _, phase := range []string{"apply", "save"} {
		t.Run(phase, func(t *testing.T) {
			f := newFixture(t)
			if phase == "apply" {
				f.device.applyErr = errors.New("disconnect after write")
			} else {
				f.device.saveErr = errors.New("commit response lost")
			}
			if _, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan); !errors.Is(err, deploy.ErrUncertain) {
				t.Fatal(err)
			}
			if _, _, err := f.store.Current(context.Background(), "fw"); !errors.Is(err, snapshot.ErrUnavailable) {
				t.Fatal("stale baseline available", err)
			}
			if _, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan); !errors.Is(err, deploy.ErrPending) {
				t.Fatal("pending apply not rejected", err)
			}
			if phase == "apply" {
				// The running graph matches but persistence does not: recovery may
				// neither run save implicitly nor publish a deployable snapshot.
				if _, err := f.engine.Recover(context.Background(), "op", f.plan); !errors.Is(err, deploy.ErrUncertain) {
					t.Fatal("running-only match proved persistence", err)
				}
				f.device.mu.Lock()
				f.device.saved = f.device.after
				f.device.mu.Unlock()
			}
			r, err := f.engine.Recover(context.Background(), "op", f.plan)
			if err != nil || r.Phase != deploy.Published || !r.Recovered {
				t.Fatal(r, err)
			}
			if f.device.executes != 1 || (phase == "apply" && f.device.saves != 0) || (phase == "save" && f.device.saves != 1) {
				t.Fatal("recovery replayed writes")
			}
		})
	}
}

func TestDeniedAuthorizationNeverWritesAndReleasesVerifiedBaseline(t *testing.T) {
	f := newFixture(t)
	denied := errors.New("denied")
	f.engine.Authorizer = deploy.AuthorizeFunc(func(context.Context, deploy.Authorization) error { return denied })
	if _, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan); !errors.Is(err, denied) {
		t.Fatal(err)
	}
	if f.device.executes != 0 || f.device.saves != 0 {
		t.Fatal("authorization bypass")
	}
	if _, _, err := f.store.Current(context.Background(), "fw"); err != nil {
		t.Fatal("prewrite failure stranded verified baseline", err)
	}
}

func TestReadbackMismatchArchivesActualEvidenceAndRetainsReservation(t *testing.T) {
	f := newFixture(t)
	f.device.badReadback = true
	if _, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan); !errors.Is(err, deploy.ErrUncertain) {
		t.Fatal(err)
	}
	m, err := f.store.Manifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m.Devices["fw"].Complete || m.Devices["fw"].Revision == f.expected || m.Reservations["fw"].Token != "op" {
		t.Fatal("readback mismatch left stale authoritative state", m)
	}
	fw, err := f.store.Load(context.Background(), m.Devices["fw"].Revision)
	if err != nil || fw.Rules()[0].Record().Log != fm.Known {
		t.Fatal("actual observed change was not archived", err)
	}
}

func TestMissingReceiptsCannotAuthorizeSave(t *testing.T) {
	f := newFixture(t)
	f.device.omitReceipts = true
	if _, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan); !errors.Is(err, deploy.ErrUncertain) {
		t.Fatal(err)
	}
	if f.device.saves != 0 {
		t.Fatal("aggregate success bypassed per-command receipts")
	}
}

type failPublish struct {
	deploy.Repository
	failures int
}

func (r *failPublish) Publish(ctx context.Context, f *fm.Firewall, o snapshot.PublishOptions) (snapshot.PublishResult, error) {
	if r.failures > 0 {
		r.failures--
		return snapshot.PublishResult{}, fmt.Errorf("disk unavailable")
	}
	return r.Repository.Publish(ctx, f, o)
}
func TestPublicationRetryUsesReadbackWithoutExecutingAgain(t *testing.T) {
	f := newFixture(t)
	f.engine.Store = &failPublish{Repository: f.store, failures: 1}
	if _, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan); err == nil {
		t.Fatal("missing publication failure")
	}
	r, err := f.engine.Recover(context.Background(), "op", f.plan)
	if err != nil || r.Phase != deploy.Published || f.device.executes != 1 || f.device.saves != 1 {
		t.Fatal("publication retry replayed deployment", r, err)
	}
}

func TestRecoveryProvesRunningAndSavedBaselineBeforeReleasing(t *testing.T) {
	f := newFixture(t)
	f.device.applyErr = errors.New("write status lost")
	if _, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan); !errors.Is(err, deploy.ErrUncertain) {
		t.Fatal(err)
	}
	f.device.running, f.device.saved = f.device.before, f.device.before
	r, err := f.engine.Recover(context.Background(), "op", f.plan)
	if err != nil || r.Phase != deploy.Aborted {
		t.Fatal("independent unchanged proof did not release", r, err)
	}
	if _, _, err := f.store.Current(context.Background(), "fw"); err != nil {
		t.Fatal(err)
	}
	if f.device.executes != 1 || f.device.saves != 0 {
		t.Fatal("recovery wrote device")
	}
}

type faultJournal struct {
	deploy.Journal
	mu    sync.Mutex
	when  func(deploy.Record) bool
	after bool
	fired bool
}
type faultLease struct {
	deploy.Lease
	journal *faultJournal
}

func (j *faultJournal) Acquire(ctx context.Context, id string) (deploy.Lease, error) {
	l, err := j.Journal.Acquire(ctx, id)
	if err != nil {
		return nil, err
	}
	return &faultLease{l, j}, nil
}
func (l *faultLease) Save(ctx context.Context, r deploy.Record) (deploy.Record, error) {
	l.journal.mu.Lock()
	fail := !l.journal.fired && l.journal.when(r)
	if fail {
		l.journal.fired = true
	}
	l.journal.mu.Unlock()
	if !fail {
		return l.Lease.Save(ctx, r)
	}
	if l.journal.after {
		if _, err := l.Lease.Save(ctx, r); err != nil {
			return deploy.Record{}, err
		}
	}
	return deploy.Record{}, errors.New("injected durable journal interruption")
}

func TestReceiptJournalFailureStopsSaveAndCannotReplayEvenWhenIntentReachedDisk(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprint(after), func(t *testing.T) {
			f := newFixture(t)
			f.engine.Journal = &faultJournal{Journal: f.journal, after: after, when: func(r deploy.Record) bool { return len(r.Receipts) == 1 }}
			if _, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan); err == nil {
				t.Fatal("lost journal failure")
			}
			if f.device.saves != 0 {
				t.Fatal("continued after receipt persistence failed")
			}
			if _, _, err := f.store.Current(context.Background(), "fw"); !errors.Is(err, snapshot.ErrUnavailable) {
				t.Fatal("lost reservation", err)
			}
			f.device.saved = f.device.after
			if _, err := f.engine.Recover(context.Background(), "op", f.plan); err != nil {
				t.Fatal(err)
			}
			if f.device.executes != 1 {
				t.Fatal("recovery replayed uncertain write")
			}
		})
	}
}

func TestRecoveryAfterPublicationButBeforeFinalJournalRecordIsIdempotent(t *testing.T) {
	f := newFixture(t)
	f.engine.Journal = &faultJournal{Journal: f.journal, when: func(r deploy.Record) bool { return r.Phase == deploy.Published }}
	if _, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan); !errors.Is(err, deploy.ErrPending) {
		t.Fatal(err)
	}
	opens := f.device.opens
	r, err := f.engine.Recover(context.Background(), "op", f.plan)
	if err != nil || r.Phase != deploy.Published {
		t.Fatal(r, err)
	}
	if f.device.opens != opens || f.device.executes != 1 {
		t.Fatal("already published operation reopened device")
	}
}

func TestConcurrentSameOperationExecutesOnce(t *testing.T) {
	f := newFixture(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() { _, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan); results <- err })
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.device.executes != 1 || f.device.saves != 1 || f.device.active != 0 {
		t.Fatal("same operation executed concurrently")
	}
}

package operations_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/device"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
)

type batchDevices struct {
	devices   map[string]*nativeDevice
	uncertain string
}
type batchSession struct {
	deploy.Session
	name  string
	owner *batchDevices
}

func (b *batchDevices) Open(ctx context.Context, name string) (deploy.Session, error) {
	s, err := b.devices[name].Open(ctx, "pan")
	if err != nil {
		return nil, err
	}
	return &batchSession{Session: s, name: name, owner: b}, nil
}
func (s *batchSession) Read(ctx context.Context, view device.View) (device.Capture, error) {
	c, err := s.Session.Read(ctx, view)
	c.Metadata.Device = s.name
	return c, err
}
func (s *batchSession) Execute(ctx context.Context, commands []string, receipt deploy.ReceiptFunc) (deploy.Outcome, error) {
	r, err := s.Session.Execute(ctx, commands, receipt)
	if s.owner.uncertain == s.name && err == nil {
		// Independently visible persistence, but no Save receipt: recovery must
		// establish it through fresh running AND saved reads, never another write.
		s.owner.devices[s.name].saved = s.owner.devices[s.name].running
		return r, errors.New("synthetic lost response; do-not-persist-error")
	}
	return r, err
}

type batchFixture struct {
	store          *snapshot.Store
	journal        *deploy.FileJournal
	devices        *batchDevices
	report         operations.BatchReport
	selections     []operations.Selection
	root           string
	authorizations []deploy.Authorization
	deny           string
	onAuthorize    func()
	closeErr       error
}

func newBatchFixture(t *testing.T) *batchFixture {
	t.Helper()
	b := &batchFixture{root: t.TempDir(), devices: &batchDevices{devices: map[string]*nativeDevice{}}}
	var err error
	b.store, err = snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b.journal, err = deploy.OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var requests []operations.AccessRequest
	for _, name := range []string{"one", "two", "unselected"} {
		fw := parseNative(t, panBase, fm.Metadata{Device: name, Vendor: "paloalto"})
		if _, err := b.store.Publish(t.Context(), fw, snapshot.PublishOptions{PublicationID: name}); err != nil {
			t.Fatal(err)
		}
		b.devices.devices[name] = &nativeDevice{running: panBase, saved: panBase}
		requests = append(requests, operations.AccessRequest{ID: name, Traffic: requestTraffic(t, "192.0.2.10/32", "198.51.100.10/32", 443), Targets: []operations.AccessTarget{{Device: name, Request: policy.Request{FromZone: "inside", ToZone: "outside"}}}})
	}
	requests = append(requests, operations.AccessRequest{ID: "unresolved", Traffic: requests[0].Traffic, Targets: []operations.AccessTarget{{Device: "missing"}}})
	d, err := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: b.store})
	if err != nil {
		t.Fatal(err)
	}
	b.report, err = d.Design(t.Context(), operations.BatchRequest{Version: 1, Requests: requests})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range b.report.Devices {
		if p.Device != "unselected" {
			b.selections = append(b.selections, operations.Selection{Device: p.Device, Revision: p.Revision, PlanDigest: p.Batch.Plan.Digest()})
		}
	}
	if len(b.selections) != 2 || len(b.report.Issues) == 0 {
		t.Fatal("invalid fixture", b.report)
	}
	return b
}
func (b *batchFixture) executor(t *testing.T) *operations.BatchExecutor {
	t.Helper()
	var journal deploy.Journal = b.journal
	if b.closeErr != nil {
		journal = batchClosingJournal{Journal: journal, err: b.closeErr}
	}
	e, err := deploy.New(deploy.Options{Store: b.store, Journal: journal, Sessions: b.devices, Parser: vendors.Parser{}, Authorizer: deploy.AuthorizeFunc(func(_ context.Context, a deploy.Authorization) error {
		b.authorizations = append(b.authorizations, a)
		if b.onAuthorize != nil {
			b.onAuthorize()
		}
		if a.Device == b.deny {
			return errors.New("synthetic authorization denied")
		}
		return nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := operations.NewBatchExecutor(b.root, e, b.store)
	if err != nil {
		t.Fatal(err)
	}
	return executor
}

type batchClosingJournal struct {
	deploy.Journal
	err error
}
type batchClosingLease struct {
	deploy.Lease
	err error
}

func (j batchClosingJournal) Acquire(ctx context.Context, id string) (deploy.Lease, error) {
	l, err := j.Journal.Acquire(ctx, id)
	if err != nil {
		return l, err
	}
	return batchClosingLease{Lease: l, err: j.err}, nil
}
func (l batchClosingLease) Close() error { return errors.Join(l.Lease.Close(), l.err) }

func TestBatchExecutionKeepsConfirmedTerminalWhenLeaseCloseFails(t *testing.T) {
	b := newBatchFixture(t)
	b.closeErr = errors.New("lease close failed")
	e := b.executor(t)
	p, err := e.Prepare(t.Context(), "cleanup", b.report, b.selections)
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Apply(t.Context(), p.ID, p.Digest)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range r.Devices {
		if row.Status != operations.ExecutionApplied || !row.Result.Terminal() || row.Result.Phase != deploy.Published || !errors.Is(row.Error, b.closeErr) || row.Code == "recovery_required" {
			t.Fatalf("confirmed publication requires recovery: %+v", row)
		}
	}
	if _, err := e.Apply(t.Context(), p.ID, p.Digest); err != nil {
		t.Fatal(err)
	}
	for _, d := range b.devices.devices {
		if d.executes > 1 || d.saves > 1 {
			t.Fatal("terminal retry replayed writes")
		}
	}
}
func TestBatchExecutionDurableSelectionRestartAndIndependentUncertainty(t *testing.T) {
	b := newBatchFixture(t)
	e := b.executor(t)
	prepared, err := e.Prepare(t.Context(), "ticket-1", b.report, b.selections)
	if err != nil || prepared.Digest == "" || len(prepared.Review.Issues) == 0 {
		t.Fatal(prepared, err)
	}
	if len(b.authorizations) != 0 {
		t.Fatal("prepare authorized writes")
	}
	again, err := e.Prepare(t.Context(), "ticket-1", b.report, b.selections)
	if err != nil || again.Digest != prepared.Digest {
		t.Fatal("not idempotent", err)
	}
	if _, err := e.Prepare(t.Context(), "ticket-1", b.report, b.selections[:1]); !errors.Is(err, operations.ErrSelectionConflict) {
		t.Fatal(err)
	}
	if _, err := e.Apply(t.Context(), "ticket-1", "wrong"); err == nil {
		t.Fatal("unbound selection")
	}
	b.devices.uncertain = "one"
	result, err := b.executor(t).Apply(t.Context(), "ticket-1", prepared.Digest)
	if err != nil || len(result.Devices) != 2 || result.Devices[0].Status != operations.ExecutionUncertain || result.Devices[1].Status != operations.ExecutionApplied || len(result.Review.Issues) == 0 {
		t.Fatal(result, err)
	}
	if b.devices.devices["unselected"].opens != 0 {
		t.Fatal("unselected device opened")
	}
	for i, a := range b.authorizations {
		if a.Device != b.selections[i].Device || a.BaselineRevision != b.selections[i].Revision || a.PlanDigest != b.selections[i].PlanDigest || a.Operation != result.Devices[i].Operation {
			t.Fatal("authorization binding", a)
		}
	}
	result, err = b.executor(t).Apply(t.Context(), "ticket-1", prepared.Digest)
	if err != nil || result.Devices[0].Status != operations.ExecutionUncertain || b.devices.devices["one"].executes != 1 || b.devices.devices["two"].executes != 1 {
		t.Fatal("replay", result, err)
	}
	result, err = b.executor(t).Recover(t.Context(), "ticket-1", prepared.Digest)
	if err != nil || result.Devices[0].Status != operations.ExecutionApplied || result.Devices[1].Status != operations.ExecutionApplied {
		t.Fatal("recovery", result, err)
	}
	for _, name := range []string{"one", "two"} {
		d := b.devices.devices[name]
		if d.executes != 1 || d.opens != d.closes || d.active != 0 || d.token != "" {
			t.Fatal("ownership", name, d)
		}
	}
	if b.devices.devices["one"].saves != 0 {
		t.Fatal("recovery saved")
	}
}
func TestBatchExecutionAbortedDriftAndCancellation(t *testing.T) {
	for _, mode := range []string{"denied", "drift", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			b := newBatchFixture(t)
			e := b.executor(t)
			p, err := e.Prepare(t.Context(), mode, b.report, b.selections)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "denied" {
				b.deny = "one"
			}
			if mode == "drift" {
				_, head, _ := b.store.Current(t.Context(), "one")
				changed := parseNative(t, panBase+"set address external ip-netmask 203.0.113.1/32\n", fm.Metadata{Device: "one", Vendor: "paloalto"})
				if _, err := b.store.Publish(t.Context(), changed, snapshot.PublishOptions{Expected: head.Revision, PublicationID: "drift"}); err != nil {
					t.Fatal(err)
				}
			}
			ctx := t.Context()
			if mode == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			r, err := e.Apply(ctx, mode, p.Digest)
			if mode == "cancelled" {
				if !errors.Is(err, context.Canceled) || len(b.authorizations) != 0 {
					t.Fatal(r, err)
				}
				return
			}
			if err != nil || r.Devices[0].Status != operations.ExecutionAborted || r.Devices[0].Error == nil || r.Devices[1].Status != operations.ExecutionApplied || b.devices.devices["one"].opens != 0 {
				t.Fatal(r, err)
			}
			r, err = e.Apply(t.Context(), mode, p.Digest)
			if err != nil || r.Devices[0].Status != operations.ExecutionAborted {
				t.Fatal(r, err)
			}
			r, err = b.executor(t).Recover(t.Context(), mode, p.Digest)
			if err != nil || r.Devices[0].Status != operations.ExecutionAborted || b.devices.devices["one"].opens != 0 {
				t.Fatal(r, err)
			}
		})
	}
}
func TestBatchExecutionMaterialTamperingStopsBeforeSessions(t *testing.T) {
	b := newBatchFixture(t)
	e := b.executor(t)
	p, err := e.Prepare(t.Context(), "tamper", b.report, b.selections)
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(b.root, "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	f, err := os.OpenFile(files[0], os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(" ")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.executor(t).Apply(t.Context(), "tamper", p.Digest); err == nil {
		t.Fatal("tampering accepted")
	}
	if len(b.authorizations) != 0 {
		t.Fatal("tampering authorized")
	}
}

func TestBatchExecutionCancellationLeavesUnstartedPeersRecoverable(t *testing.T) {
	b := newBatchFixture(t)
	e := b.executor(t)
	p, err := e.Prepare(t.Context(), "cancel-midway", b.report, b.selections)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	b.onAuthorize = cancel
	r, err := e.Apply(ctx, p.ID, p.Digest)
	if !errors.Is(err, context.Canceled) || len(r.Devices) != 2 || r.Devices[1].Status != operations.ExecutionCancelled || len(b.authorizations) != 1 {
		t.Fatal(r, err)
	}
	r, err = b.executor(t).Recover(t.Context(), p.ID, p.Digest)
	if err != nil || r.Devices[0].Status != operations.ExecutionAborted || r.Devices[1].Status != operations.ExecutionUnstarted {
		t.Fatal(r, err)
	}
	for _, d := range b.devices.devices {
		if d.opens != 0 || d.executes != 0 {
			t.Fatal("cancel/recovery opened device", d)
		}
	}
}

type missingBatchRevision struct {
	operations.RevisionLoader
	revision string
}

func (s missingBatchRevision) Load(ctx context.Context, revision string) (*fm.Firewall, error) {
	if revision == s.revision {
		return nil, errors.New("synthetic missing immutable revision")
	}
	return s.RevisionLoader.Load(ctx, revision)
}
func TestBatchExecutionReconstructionFailureKeepsIndependentPeer(t *testing.T) {
	b := newBatchFixture(t)
	e := b.executor(t)
	p, err := e.Prepare(t.Context(), "missing-blob", b.report, b.selections)
	if err != nil {
		t.Fatal(err)
	}
	// A fresh process still has its deployment engine, but cannot load one
	// original blob. It must not substitute that device's latest/observed graph.
	engine, err := deploy.New(deploy.Options{Store: b.store, Journal: b.journal, Sessions: b.devices, Parser: vendors.Parser{}, Authorizer: deploy.AuthorizeFunc(func(context.Context, deploy.Authorization) error { return nil })})
	if err != nil {
		t.Fatal(err)
	}
	e, err = operations.NewBatchExecutor(b.root, engine, missingBatchRevision{RevisionLoader: b.store, revision: b.selections[0].Revision})
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Apply(t.Context(), p.ID, p.Digest)
	if err != nil || r.Devices[0].Code != "reconstruction_failed" || r.Devices[1].Status != operations.ExecutionApplied || b.devices.devices["one"].opens != 0 {
		t.Fatal(r, err)
	}
}

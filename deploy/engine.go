package deploy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/device"
	capturegraph "github.com/gatework/firemon/internal/capture"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/snapshot"
)

type attempt struct {
	mu           sync.Mutex
	lease        Lease
	record       Record
	receiptError error
}

func (a *attempt) update(ctx context.Context, change func(*Record)) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.updateLocked(ctx, change)
}
func (a *attempt) updateLocked(ctx context.Context, change func(*Record)) error {
	next := a.record
	next.Receipts = slices.Clone(next.Receipts)
	change(&next)
	saved, err := a.lease.Save(ctx, next)
	if err == nil {
		a.record = saved
	}
	return err
}
func (a *attempt) get() Record {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.record
	r.Receipts = slices.Clone(r.Receipts)
	return r
}
func (a *attempt) receipts(phase string, count int) ReceiptFunc {
	return func(ctx context.Context, r Receipt) error {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.receiptError != nil {
			return a.receiptError
		}
		if r.Index < 0 || r.Index >= count || len(r.ResponseDigest) > 128 {
			a.receiptError = ErrInvalid
			return ErrInvalid
		}
		r.Phase = phase
		for _, prior := range a.record.Receipts {
			if prior.Phase == phase && prior.Index == r.Index {
				if prior == r {
					return nil
				}
				a.receiptError = ErrJournalConflict
				return a.receiptError
			}
		}
		a.receiptError = a.updateLocked(ctx, func(next *Record) {
			next.Receipts = append(next.Receipts, r)
			if phase == "save" && r.Written && r.Confirmed && r.Durable {
				next.Saved = true
			}
		})
		return a.receiptError
	}
}
func (a *attempt) applied(count int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.receiptError != nil {
		return false
	}
	n := 0
	for _, r := range a.record.Receipts {
		if r.Phase == "apply" && r.Written && r.Confirmed {
			n++
		}
	}
	return n == count
}
func (a *attempt) receiptFailure() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.receiptError
}

func (e Engine) context(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := e.timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return context.WithTimeout(ctx, timeout)
}
func (e Engine) validate(p *plan.Plan, authorize bool) error {
	if dependency.Nil(e.store) || dependency.Nil(e.journal) || dependency.Nil(e.sessions) || dependency.Nil(e.parser) || authorize && dependency.Nil(e.authorizer) || p == nil || p.Before() == nil || p.After() == nil || p.Digest() == "" {
		return ErrInvalid
	}
	if len(p.Commands()) > 10000 {
		return ErrInvalid
	}
	return nil
}

// Apply claims one durable operation before opening a device. Reusing a completed
// operation is idempotent; reusing an uncertain operation never retries writes.
func (e Engine) Apply(ctx context.Context, operation, expected string, p *plan.Plan) (result Result, err error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := e.validate(p, true); err != nil {
		return Result{}, err
	}
	if operation == "" || expected == "" {
		return Result{}, ErrInvalid
	}
	ctx, cancel := e.context(ctx)
	defer cancel()
	lease, err := e.journal.Acquire(ctx, operation)
	if err != nil {
		if !dependency.Nil(lease) {
			err = errors.Join(err, lease.Close())
		}
		return Result{}, err
	}
	if dependency.Nil(lease) {
		return Result{}, ErrInvalid
	}
	defer func() { err = errors.Join(err, lease.Close()) }()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	prior, err := lease.Load(ctx)
	if err == nil {
		if prior.PlanDigest != p.Digest() || prior.BaselineRevision != expected || prior.Device != p.Before().Metadata().Device || prior.Context != p.Before().Metadata().Context {
			return Result{}, ErrJournalConflict
		}
		if prior.Phase == Published {
			return Result{Operation: operation, Revision: prior.PublishedRevision, Phase: Published}, nil
		}
		return Result{Operation: operation, Phase: prior.Phase}, ErrPending
	}
	if !errors.Is(err, ErrJournalNotFound) {
		return Result{}, err
	}
	metadata := p.Before().Metadata()
	a := &attempt{lease: lease, record: Record{ID: operation, Device: metadata.Device, Vendor: metadata.Vendor, Context: metadata.Context, BaselineRevision: expected, ExpectedRevision: expected, PlanDigest: p.Digest(), Phase: Prepared}}
	if err := a.update(ctx, func(*Record) {}); err != nil {
		return Result{}, err
	}
	current, head, err := e.store.Current(ctx, metadata.Device)
	if err != nil {
		return Result{}, errors.Join(err, a.update(ctx, func(r *Record) { r.Phase = Aborted }))
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if current == nil {
		return Result{}, errors.Join(ErrInvalid, a.update(ctx, func(r *Record) { r.Phase = Aborted }))
	}
	if head.Revision != expected || current.SemanticDigest() != p.Before().SemanticDigest() {
		return Result{}, errors.Join(snapshot.ErrConflict, a.update(ctx, func(r *Record) { r.Phase = Aborted }))
	}
	if err := e.authorizer.Authorize(ctx, Authorization{Operation: operation, Device: metadata.Device, BaselineRevision: expected, PlanDigest: p.Digest()}); err != nil {
		return Result{}, errors.Join(err, a.update(ctx, func(r *Record) { r.Phase = Aborted }))
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := e.store.Reserve(ctx, metadata.Device, expected, operation); err != nil {
		return Result{}, errors.Join(err, a.update(ctx, func(r *Record) { r.Phase = Aborted }))
	}
	if err := a.update(ctx, func(r *Record) { r.Phase = Reserved }); err != nil {
		return Result{}, errors.Join(ErrPending, err)
	}
	session, err := e.sessions.Open(ctx, metadata.Device)
	if err != nil {
		if !dependency.Nil(session) {
			err = errors.Join(err, session.Close())
		}
		return Result{}, e.uncertain(ctx, a, err)
	}
	if dependency.Nil(session) {
		return Result{}, e.uncertain(ctx, a, ErrInvalid)
	}
	defer func() {
		if !dependency.Nil(session) {
			err = errors.Join(err, session.Close())
		}
	}()
	if err := ctx.Err(); err != nil {
		return Result{}, e.uncertain(ctx, a, err)
	}
	{
		var token [24]byte
		if _, err := rand.Read(token[:]); err != nil {
			return Result{}, e.uncertain(ctx, a, err)
		}
		if err := a.update(ctx, func(r *Record) { r.ConfigurationToken = hex.EncodeToString(token[:]) }); err != nil {
			return Result{}, errors.Join(ErrPending, err)
		}
		if err := session.BeginConfiguration(ctx, a.get().ConfigurationToken); err != nil {
			return Result{}, e.uncertain(ctx, a, err)
		}
	}
	baseline, err := e.read(ctx, session, device.Running, a.get())
	if err != nil {
		return Result{}, e.uncertainRunning(ctx, a, baseline, err)
	}
	if err := p.VerifyBaseline(ctx, baseline); err != nil {
		return Result{}, errors.Join(ErrUncertain, err, e.observe(ctx, a, baseline))
	}
	commands := p.Commands()
	if len(commands) == 0 {
		if err := e.endConfiguration(ctx, session, a); err != nil {
			return Result{}, e.uncertain(ctx, a, err)
		}
		if err := e.abortUnchanged(ctx, a, Published); err != nil {
			return Result{}, err
		}
		return Result{Operation: operation, Revision: expected, Phase: Published}, nil
	}
	if err := a.update(ctx, func(r *Record) { r.Phase = WriteIntent; r.WriteStarted = true }); err != nil {
		// Intent persistence may have succeeded even when fsync reports an error.
		// Do not write or release ownership; recovery will inspect the record.
		return Result{}, errors.Join(ErrPending, err)
	}
	applied, err := session.Execute(ctx, commands, a.receipts("apply", len(commands)))
	if err != nil || !applied.Complete || !a.applied(len(commands)) {
		return Result{}, e.uncertain(ctx, a, err)
	}
	if err := a.update(ctx, func(r *Record) { r.Phase = SaveIntent }); err != nil {
		return Result{}, e.uncertain(ctx, a, err)
	}
	saved, err := session.Save(ctx, a.receipts("save", 10000))
	if err != nil || !saved.Complete || !saved.Durable || !a.get().Saved || a.receiptFailure() != nil {
		return Result{}, e.uncertain(ctx, a, err)
	}
	if err := a.update(ctx, func(r *Record) { r.Phase = PersistenceConfirmed }); err != nil {
		return Result{}, e.uncertain(ctx, a, err)
	}
	if err := e.endConfiguration(ctx, session, a); err != nil {
		return Result{}, e.uncertain(ctx, a, err)
	}
	if err := session.Close(); err != nil {
		return Result{}, e.uncertain(ctx, a, err)
	}
	session = nil
	return e.readback(ctx, a, p, false)
}

// Recover performs no Execute or Save calls. It requires fresh running evidence
// and, when no durable confirmation was journaled, fresh saved-state evidence.
func (e Engine) Recover(ctx context.Context, operation string, p *plan.Plan) (result Result, err error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := e.validate(p, false); err != nil {
		return Result{}, err
	}
	ctx, cancel := e.context(ctx)
	defer cancel()
	lease, err := e.journal.Acquire(ctx, operation)
	if err != nil {
		if !dependency.Nil(lease) {
			err = errors.Join(err, lease.Close())
		}
		return Result{}, err
	}
	if dependency.Nil(lease) {
		return Result{}, ErrInvalid
	}
	defer func() { err = errors.Join(err, lease.Close()) }()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	r, err := lease.Load(ctx)
	if err != nil {
		return Result{}, err
	}
	if r.PlanDigest != p.Digest() || r.Device != p.Before().Metadata().Device || r.Context != p.Before().Metadata().Context {
		return Result{}, ErrJournalConflict
	}
	if r.Phase == Published || r.Phase == Aborted {
		return Result{Operation: operation, Revision: r.PublishedRevision, Phase: r.Phase, Recovered: true}, nil
	}
	a := &attempt{lease: lease, record: r}
	m, err := e.store.Manifest(ctx)
	if err != nil {
		return Result{}, err
	}
	if publication, ok := m.Publications[operation+":complete"]; ok {
		if publication.Device != r.Device || publication.Revision != r.ObservedRevision || publication.Reservation != operation || publication.KeepReservation {
			return Result{}, ErrJournalConflict
		}
		fw, err := e.store.Load(ctx, publication.Revision)
		if err != nil {
			return Result{}, err
		}
		if fw == nil {
			return Result{}, ErrInvalid
		}
		if r.Applied {
			_, err = p.Verify(ctx, fw)
		} else {
			err = p.VerifyBaseline(ctx, fw)
		}
		if err != nil {
			return Result{}, err
		}
		phase := Published
		if !r.Applied {
			phase = Aborted
		}
		if err := a.update(ctx, func(r *Record) { r.Phase = phase; r.PublishedRevision = publication.Revision }); err != nil {
			return Result{}, err
		}
		return Result{Operation: operation, Revision: publication.Revision, Phase: phase, Recovered: true}, nil
	}
	reservation, ok := m.Reservations[r.Device]
	if !ok {
		if r.Phase == BaselineConfirmed && m.Devices[r.Device].Revision == r.BaselineRevision {
			phase := Aborted
			if r.Applied {
				phase = Published
			}
			if err := a.update(ctx, func(r *Record) { r.Phase = phase; r.PublishedRevision = r.BaselineRevision }); err != nil {
				return Result{}, err
			}
			return Result{Operation: operation, Revision: r.BaselineRevision, Phase: phase, Recovered: true}, nil
		}
		if !r.WriteStarted && m.Devices[r.Device].Revision == r.BaselineRevision {
			if err := a.update(ctx, func(r *Record) { r.Phase = Aborted }); err != nil {
				return Result{}, err
			}
			return Result{Operation: operation, Phase: Aborted, Recovered: true}, nil
		}
		return Result{}, ErrPending
	}
	if reservation.Token != operation {
		return Result{}, snapshot.ErrReserved
	}
	if r.ExpectedRevision != reservation.Expected {
		if err := a.update(ctx, func(r *Record) { r.ExpectedRevision = reservation.Expected }); err != nil {
			return Result{}, err
		}
	}
	return e.readback(ctx, a, p, true)
}

func (e Engine) readback(ctx context.Context, a *attempt, p *plan.Plan, recovered bool) (result Result, err error) {
	r := a.get()
	session, err := e.sessions.Open(ctx, r.Device)
	if err != nil {
		if !dependency.Nil(session) {
			err = errors.Join(err, session.Close())
		}
		return Result{}, e.uncertain(ctx, a, err)
	}
	if dependency.Nil(session) {
		return Result{}, e.uncertain(ctx, a, ErrInvalid)
	}
	defer func() { err = errors.Join(err, session.Close()) }()
	if recovered {
		if err := e.endConfiguration(ctx, session, a); err != nil {
			return Result{}, e.uncertain(ctx, a, err)
		}
	}
	observed, err := e.read(ctx, session, device.Running, r)
	if err != nil {
		return Result{}, e.uncertainRunning(ctx, a, observed, err)
	}
	_, afterErr := p.Verify(ctx, observed)
	if afterErr == nil {
		// Recovery can observe external changes before our write intent, or after
		// an earlier save receipt. Neither proves the current running graph durable.
		if recovered || !r.Saved {
			saved, readErr := e.read(ctx, session, device.Saved, r)
			if readErr != nil {
				return Result{}, errors.Join(e.uncertain(ctx, a, readErr), e.observe(ctx, a, observed))
			}
			if _, err := p.Verify(ctx, saved); err != nil {
				return Result{}, errors.Join(ErrUncertain, err, e.observe(ctx, a, observed))
			}
			if err := a.update(ctx, func(r *Record) { r.Saved = true }); err != nil {
				return Result{}, e.uncertain(ctx, a, err)
			}
		}
		return e.publish(ctx, a, observed, true, recovered)
	}
	if recovered && p.VerifyBaseline(ctx, observed) == nil {
		if r.WriteStarted {
			saved, readErr := e.read(ctx, session, device.Saved, r)
			if readErr != nil {
				return Result{}, errors.Join(e.uncertain(ctx, a, readErr), e.observe(ctx, a, observed))
			}
			if err := p.VerifyBaseline(ctx, saved); err != nil {
				return Result{}, errors.Join(ErrUncertain, err, e.observe(ctx, a, observed))
			}
		}
		// After an uncertain observation has advanced the head, republish the
		// freshly proved baseline instead of releasing an incomplete revision.
		if a.get().ExpectedRevision != r.BaselineRevision {
			return e.publish(ctx, a, observed, false, true)
		}
		if err := e.abortUnchanged(ctx, a, Aborted); err != nil {
			return Result{}, err
		}
		return Result{Operation: r.ID, Revision: r.BaselineRevision, Phase: Aborted, Recovered: true}, nil
	}
	return Result{}, errors.Join(ErrUncertain, afterErr, e.observe(ctx, a, observed))
}

func (e Engine) endConfiguration(ctx context.Context, session Session, a *attempt) error {
	r := a.get()
	if r.ConfigurationToken == "" || r.ConfigurationReleased {
		return nil
	}
	if err := session.EndConfiguration(ctx, r.ConfigurationToken); err != nil {
		return err
	}
	return a.update(ctx, func(r *Record) { r.ConfigurationReleased = true })
}

func (e Engine) read(ctx context.Context, session Session, view device.View, r Record) (*fm.Firewall, error) {
	capture, readErr := session.Read(ctx, view)
	if capture.Metadata.Device != r.Device || capture.Metadata.Vendor != r.Vendor || capture.Metadata.Context != r.Context {
		return nil, errors.Join(readErr, fmt.Errorf("%w: capture identity mismatch", ErrInvalid))
	}
	code, message := "readback-parse-failed", "native parser could not establish the captured configuration"
	if readErr != nil {
		code, message = "readback-capture-failed", "native configuration capture was interrupted"
	}
	return capturegraph.Graph(ctx, e.parser, capture.Source, capture.Metadata, readErr, ErrInvalid, capturegraph.Diagnostics{
		Failed:     fm.Diagnostic{Code: code, Message: message},
		Incomplete: fm.Diagnostic{Code: "readback-parse-failed", Message: "capture completeness was not established"},
	})
}
func (e Engine) abortUnchanged(ctx context.Context, a *attempt, phase Phase) error {
	r := a.get()
	// Callers have proved the baseline before writes or independently compared
	// both running and saved configurations during recovery. Persist that proof
	// before releasing, so a crash after release is distinguishable from loss of
	// an uncertain reservation.
	if err := a.update(ctx, func(r *Record) { r.Phase = BaselineConfirmed; r.Applied = phase == Published }); err != nil {
		return err
	}
	if err := e.store.ReleaseUnchanged(ctx, r.Device, r.ID, r.BaselineRevision); err != nil {
		return err
	}
	return a.update(ctx, func(r *Record) { r.Phase = phase; r.PublishedRevision = r.BaselineRevision })
}
func (e Engine) uncertain(ctx context.Context, a *attempt, cause error) error {
	return errors.Join(ErrUncertain, cause, a.update(ctx, func(r *Record) { r.Phase = Uncertain }))
}

func (e Engine) uncertainRunning(ctx context.Context, a *attempt, observed *fm.Firewall, cause error) error {
	if observed == nil {
		return e.uncertain(ctx, a, cause)
	}
	// Finish only local evidence persistence after cancellation. Device work is
	// already stopped; the reservation remains until independent recovery.
	evidenceCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return errors.Join(e.uncertain(evidenceCtx, a, cause), e.observe(evidenceCtx, a, observed))
}

func (e Engine) observe(ctx context.Context, a *attempt, fw *fm.Firewall) error {
	d := fw.Export()
	d.Diagnostics = append(d.Diagnostics, fm.Diagnostic{Code: "unverified-deployment", Message: "observed device state has not passed effect and persistence verification"})
	incomplete, err := fm.Seal(d)
	if err != nil {
		return err
	}
	r := a.get()
	revision, err := e.store.Archive(ctx, incomplete)
	if err != nil {
		return err
	}
	if err := a.update(ctx, func(r *Record) { r.Phase = Uncertain; r.ObservedRevision = revision }); err != nil {
		return err
	}
	result, err := e.store.Publish(ctx, incomplete, snapshot.PublishOptions{Expected: r.ExpectedRevision, PublicationID: r.ID + ":observation:" + revision, Reservation: r.ID, Live: true, KeepReservation: true})
	if err != nil {
		return err
	}
	return a.update(ctx, func(r *Record) { r.ExpectedRevision = result.Revision })
}
func (e Engine) publish(ctx context.Context, a *attempt, fw *fm.Firewall, applied, recovered bool) (Result, error) {
	revision, err := e.store.Archive(ctx, fw)
	if err != nil {
		return Result{}, errors.Join(ErrPending, err)
	}
	if err := a.update(ctx, func(r *Record) { r.Phase = ReadbackConfirmed; r.ObservedRevision = revision; r.Applied = applied }); err != nil {
		return Result{}, errors.Join(ErrPending, err)
	}
	r := a.get()
	pub, err := e.store.Publish(ctx, fw, snapshot.PublishOptions{Expected: r.ExpectedRevision, PublicationID: r.ID + ":complete", Reservation: r.ID, Live: true})
	if err != nil {
		return Result{}, errors.Join(ErrPending, err)
	}
	phase := Published
	if !applied {
		phase = Aborted
	}
	if err := a.update(ctx, func(r *Record) { r.Phase = phase; r.PublishedRevision = pub.Revision }); err != nil {
		return Result{}, errors.Join(ErrPending, err)
	}
	return Result{Operation: r.ID, Revision: pub.Revision, Phase: phase, Recovered: recovered}, nil
}

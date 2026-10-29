// Package deploy coordinates authorized device changes with durable local
// ownership, receipts, independent readback and recovery without write replay.
package deploy

import (
	"context"
	"errors"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/device"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/snapshot"
)

var (
	ErrPending         = errors.New("operation requires independent recovery")
	ErrUncertain       = errors.New("device effect or persistence is not established")
	ErrJournalFormat   = errors.New("unsupported or corrupt operation journal")
	ErrJournalConflict = errors.New("journal operation conflict")
	ErrJournalNotFound = errors.New("journal operation not found")
	ErrInvalid         = errors.New("invalid deployment request")
)

// Receipt contains evidence flags and a response digest, never raw device
// output or credentials. Index is the native script step index within Phase.
type Receipt struct {
	Phase                       string
	Index                       int
	Written, Confirmed, Durable bool
	ResponseDigest              string
}
type Outcome struct {
	Complete, Durable bool
}
type ReceiptFunc func(context.Context, Receipt) error

// Session implementations must stop on receipt errors, obey cancellation and
// never replay a possibly written command. Save must confirm business persistence
// (for example the PAN commit job), not merely observe a command prompt.
// Candidate-based devices must provide native isolation through the configuration
// lifecycle. Devices that edit running state directly explicitly handle this
// lifecycle too, for example by preflighting persistence or using no-ops.
type Session interface {
	ConfigurationSession
	device.Reader
	Execute(context.Context, []string, ReceiptFunc) (Outcome, error)
	Save(context.Context, ReceiptFunc) (Outcome, error)
}

// ConfigurationSession supplies device-side candidate isolation. Begin is called
// before the fresh baseline; its opaque ownership token is journaled first.
// End may be called by a fresh recovery session with that token. It must never
// remove another owner's lock, discard candidate changes, or replay writes.
// An uncertain release must return an error. Close only releases transport
// resources; it is not proof that an administrative device lock was removed.
type ConfigurationSession interface {
	BeginConfiguration(context.Context, string) error
	EndConfiguration(context.Context, string) error
}
type Factory interface {
	Open(context.Context, string) (Session, error)
}
type Authorization struct {
	Operation, Device, BaselineRevision, PlanDigest string
}

// Authorizer approves the exact operation before reservation, session creation
// or native configuration isolation. The locked fresh baseline is still verified
// against this approved plan before any policy command is executed.
type Authorizer interface {
	Authorize(context.Context, Authorization) error
}
type AuthorizeFunc func(context.Context, Authorization) error

func (f AuthorizeFunc) Authorize(ctx context.Context, a Authorization) error { return f(ctx, a) }

type Repository interface {
	Current(context.Context, string) (*fm.Firewall, snapshot.Head, error)
	Load(context.Context, string) (*fm.Firewall, error)
	Manifest(context.Context) (snapshot.Manifest, error)
	Archive(context.Context, *fm.Firewall) (string, error)
	Reserve(context.Context, string, string, string) error
	ReleaseUnchanged(context.Context, string, string, string) error
	Publish(context.Context, *fm.Firewall, snapshot.PublishOptions) (snapshot.PublishResult, error)
}

type Phase uint8

const (
	Prepared Phase = iota + 1
	Reserved
	WriteIntent
	SaveIntent
	PersistenceConfirmed
	ReadbackConfirmed
	Uncertain
	Published
	Aborted
	BaselineConfirmed
)

type Record struct {
	ID, Device, Vendor, BaselineRevision, ExpectedRevision, PlanDigest string
	Context                                                            string
	Sequence                                                           uint64
	Phase                                                              Phase
	WriteStarted, Saved, Applied                                       bool
	ObservedRevision, PublishedRevision                                string
	Receipts                                                           []Receipt
	// ConfigurationToken survives cancellation and process death until a
	// successful ownership-checked EndConfiguration has been journaled.
	ConfigurationToken    string
	ConfigurationReleased bool
}

// A Lease is exclusive across processes for the whole operation. A crash releases
// the OS lock, but leaves both the journal and the device reservation intact.
// Save is compare-and-swap on Record.Sequence and returns the new sequence.
type Lease interface {
	Load(context.Context) (Record, error)
	Save(context.Context, Record) (Record, error)
	Close() error
}
type Journal interface {
	Acquire(context.Context, string) (Lease, error)
}

type Options struct {
	Store      Repository
	Journal    Journal
	Sessions   Factory
	Parser     config.Parser
	Authorizer Authorizer
	// Timeout bounds a whole Apply or Recover call. Zero uses five minutes.
	Timeout time.Duration
}

// Engine privately owns the dependencies validated by New.
type Engine struct {
	store      Repository
	journal    Journal
	sessions   Factory
	parser     config.Parser
	authorizer Authorizer
	timeout    time.Duration
}

func New(options Options) (*Engine, error) {
	if dependency.Nil(options.Store) || dependency.Nil(options.Journal) || dependency.Nil(options.Sessions) || dependency.Nil(options.Parser) || dependency.Nil(options.Authorizer) || options.Timeout < 0 {
		return nil, ErrInvalid
	}
	return &Engine{store: options.Store, journal: options.Journal, sessions: options.Sessions, parser: options.Parser, authorizer: options.Authorizer, timeout: options.Timeout}, nil
}

type Result struct {
	Operation, Revision string
	Phase               Phase
	Recovered           bool
}

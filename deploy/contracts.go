// Package deploy coordinates authorized device changes with durable local
// ownership, receipts, independent readback and recovery without write replay.
package deploy

import (
	"context"
	"errors"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/snapshot"
	"time"
)

var (
	ErrPending         = errors.New("operation requires independent recovery")
	ErrUncertain       = errors.New("device effect or persistence is not established")
	ErrJournalConflict = errors.New("journal operation conflict")
	ErrJournalNotFound = errors.New("journal operation not found")
	ErrInvalid         = errors.New("invalid deployment request")
)

type View uint8

const (
	Running View = iota + 1
	Saved
)

type Capture struct {
	Source   config.Source
	Metadata fm.Metadata
}

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
type Session interface {
	Read(context.Context, View) (Capture, error)
	Execute(context.Context, []string, ReceiptFunc) (Outcome, error)
	Save(context.Context, ReceiptFunc) (Outcome, error)
	Close() error
}
type Factory interface {
	Open(context.Context, string) (Session, error)
}
type Parser interface {
	Parse(context.Context, config.Source, fm.Metadata) (*fm.Firewall, error)
}
type ParseFunc func(context.Context, config.Source, fm.Metadata) (*fm.Firewall, error)

func (f ParseFunc) Parse(ctx context.Context, s config.Source, m fm.Metadata) (*fm.Firewall, error) {
	return f(ctx, s, m)
}

type Authorization struct {
	Operation, Device, BaselineRevision, PlanDigest string
}
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
	Sequence                                                           uint64
	Phase                                                              Phase
	WriteStarted, Saved, Applied                                       bool
	ObservedRevision, PublishedRevision                                string
	Receipts                                                           []Receipt
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

type Engine struct {
	Store      Repository
	Journal    Journal
	Sessions   Factory
	Parser     Parser
	Authorizer Authorizer
	// Timeout bounds a whole Apply or Recover call. Zero uses five minutes.
	Timeout time.Duration
}
type Result struct {
	Operation, Revision string
	Phase               Phase
	Recovered           bool
}

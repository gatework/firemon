// Package projection publishes file-backed graphs to an optional host-owned database sink.
package projection

import (
	"context"
	"errors"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/snapshot"
)

type Batch struct {
	Device, Revision string
	Generation       uint64
	Complete         bool
	Firewall         *fm.Firewall
}

// Sink must atomically reject stale generations and apply duplicate revisions idempotently.
// Apply returning nil confirms the host transaction has committed.
type Sink interface {
	Apply(context.Context, Batch) error
}

// Outbox owns persisted events, immutable revisions, and cursor CAS.
type Outbox interface {
	Manifest(context.Context) (snapshot.Manifest, error)
	Load(context.Context, string) (*fm.Firewall, error)
	Acknowledge(context.Context, string, uint64, uint64) error
}

func Drain(ctx context.Context, store Outbox, name string, sink Sink) error {
	if name == "" || sink == nil {
		return errors.New("projection requires sink name and implementation")
	}
	manifest, err := store.Manifest(ctx)
	if err != nil {
		return err
	}
	cursor := manifest.Acknowledged[name]
	for _, event := range manifest.Events {
		if event.Generation <= cursor {
			continue
		}
		fw, err := store.Load(ctx, event.Revision)
		if err != nil {
			return err
		}
		if fw.Metadata().Device != event.Device || fw.Complete() != event.Complete {
			return snapshot.ErrFormat
		}
		if err = sink.Apply(ctx, Batch{Device: event.Device, Revision: event.Revision, Generation: event.Generation, Complete: event.Complete, Firewall: fw}); err != nil {
			return err
		}
		if err = store.Acknowledge(ctx, name, cursor, event.Generation); err != nil {
			return err
		}
		cursor = event.Generation
	}
	return nil
}

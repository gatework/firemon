// Package operations composes capture, native planning and durable deployment
// for hosts that own inventory, credentials, authorization and storage paths.
package operations

import (
	"context"
	"errors"
	"strings"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/deploy"
	capturegraph "github.com/gatework/firemon/internal/capture"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
)

var (
	ErrInvalid    = errors.New("invalid firewall operation request or evidence")
	ErrIncomplete = errors.New("captured firewall evidence is incomplete")
)

// CaptureStore is the publication boundary needed by Collector. The manifest
// supplies revision, reservation and prior-publication evidence before dialing.
type CaptureStore interface {
	Manifest(context.Context) (snapshot.Manifest, error)
	Publish(context.Context, *fm.Firewall, snapshot.PublishOptions) (snapshot.PublishResult, error)
}

type Collector struct {
	Store    CaptureStore
	Sessions deploy.Factory
	Parser   deploy.Parser
	// Timeout bounds capture and parsing. Zero uses five minutes. Evidence
	// publication has a separate five-second bound so cancellation cannot leave
	// an old complete head current after a partial live capture was observed.
	Timeout time.Duration
}

type CollectRequest struct {
	Device        string `json:"device"`
	Expected      string `json:"expected"`
	PublicationID string `json:"publication_id"`
}

type CollectResult struct {
	Revision   string `json:"revision"`
	Generation uint64 `json:"generation"`
	Complete   bool   `json:"complete"`
}

func operationContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return context.WithTimeout(ctx, timeout)
}

// Collect reads running state once and publishes it with revision CAS. Expected
// is the head immediately before this publication (empty for a new device).
// Retrying PublicationID with the same Device and Expected returns the recorded
// publication, including incomplete results, without reopening a session.
// A session's capture is authoritative for vendor and native context; a device
// identifier should therefore name one host-selected native context.
// An incomplete publication returns both its revision and ErrIncomplete.
func (c Collector) Collect(ctx context.Context, request CollectRequest) (result CollectResult, err error) {
	if c.Store == nil || c.Sessions == nil || c.Parser == nil || strings.TrimSpace(request.Device) == "" || strings.TrimSpace(request.PublicationID) == "" {
		return CollectResult{}, ErrInvalid
	}
	if parser, ok := c.Parser.(deploy.ParseFunc); ok && parser == nil {
		return CollectResult{}, ErrInvalid
	}
	ctx, cancel := operationContext(ctx, c.Timeout)
	defer cancel()
	manifest, err := c.Store.Manifest(ctx)
	if err != nil {
		return CollectResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return CollectResult{}, err
	}
	if prior, ok := manifest.Publications[request.PublicationID]; ok {
		return priorCollection(ctx, manifest, prior, request)
	}
	if manifest.Devices[request.Device].Revision != request.Expected {
		return CollectResult{}, snapshot.ErrConflict
	}
	if _, reserved := manifest.Reservations[request.Device]; reserved {
		return CollectResult{}, snapshot.ErrReserved
	}
	if err := ctx.Err(); err != nil {
		return CollectResult{}, err
	}
	session, err := c.Sessions.Open(ctx, request.Device)
	defer func() {
		if session != nil {
			err = errors.Join(err, session.Close())
		}
	}()
	if err != nil {
		return CollectResult{}, errors.Join(err, ctx.Err())
	}
	if session == nil {
		return CollectResult{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return CollectResult{}, err
	}
	capture, readErr := session.Read(ctx, deploy.Running)
	closeErr := session.Close()
	session = nil
	readErr = errors.Join(readErr, ctx.Err())
	if capture.Metadata.Device != request.Device || len(capture.Source.Text) > config.DefaultMaxBytes {
		return CollectResult{}, errors.Join(ErrInvalid, readErr, closeErr)
	}
	capture.Metadata, err = vendors.Normalize(capture.Metadata)
	if err != nil {
		return CollectResult{}, errors.Join(ErrInvalid, err, readErr, closeErr)
	}
	if readErr != nil {
		capture.Source.Complete = false
	}
	fw, parseErr := capturedGraph(ctx, c.Parser, capture)
	if fw == nil {
		return CollectResult{}, errors.Join(parseErr, readErr, closeErr)
	}
	publicationCtx, finish := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer finish()
	published, publishErr := c.Store.Publish(publicationCtx, fw, snapshot.PublishOptions{
		Expected: request.Expected, PublicationID: request.PublicationID, Live: true,
	})
	if publishErr != nil {
		return CollectResult{}, errors.Join(publishErr, parseErr, readErr, closeErr, ctx.Err())
	}
	result = CollectResult{Revision: published.Revision, Generation: published.Generation, Complete: fw.Complete()}
	return result, errors.Join(collectionStatus(result), parseErr, readErr, closeErr, ctx.Err())
}

func collectionStatus(result CollectResult) error {
	if !result.Complete {
		return ErrIncomplete
	}
	return nil
}

func priorCollection(ctx context.Context, manifest snapshot.Manifest, prior snapshot.Publication, request CollectRequest) (CollectResult, error) {
	if prior.Device != request.Device || prior.Reservation != "" || prior.KeepReservation {
		return CollectResult{}, snapshot.ErrConflict
	}
	var previous, published snapshot.Event
	found := false
	for _, event := range manifest.Events {
		if err := ctx.Err(); err != nil {
			return CollectResult{}, err
		}
		if event.Device != request.Device {
			continue
		}
		if event.Generation < prior.Generation && event.Generation > previous.Generation {
			previous = event
		}
		if event.Generation == prior.Generation {
			if found || event.Revision != prior.Revision {
				return CollectResult{}, snapshot.ErrConflict
			}
			published, found = event, true
		}
	}
	if !found || previous.Revision != request.Expected {
		return CollectResult{}, snapshot.ErrConflict
	}
	result := CollectResult{Revision: prior.Revision, Generation: prior.Generation, Complete: published.Complete}
	return result, collectionStatus(result)
}

func capturedGraph(ctx context.Context, parser deploy.Parser, capture deploy.Capture) (*fm.Firewall, error) {
	return capturegraph.Graph(ctx, parser, capture.Source, capture.Metadata, nil, ErrInvalid, capturegraph.Diagnostics{
		Failed:     fm.Diagnostic{Code: "capture-parse-failed", Message: "native parser could not establish the captured configuration"},
		Incomplete: fm.Diagnostic{Code: "incomplete-source", Message: "capture completeness was not established"},
	})
}

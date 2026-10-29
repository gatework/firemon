package operations_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/device"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/snapshot"
)

// A collection reader has no configuration, execute, save, journal or authorization API.
type onlyReader struct{ device.Reader }
type nilReaderFactory struct{ reader device.Reader }

func (f *nilReaderFactory) OpenReadOnly(context.Context, string) (device.Reader, error) {
	return f.reader, nil
}
func TestCollectorConstructorAndNilReaderBoundaries(t *testing.T) {
	c, store, _, req := collectionFixture(t)
	var typedNil *nilReaderFactory
	if _, err := operations.NewCollector(operations.CollectorOptions{Store: store, Sessions: typedNil, Parser: c.Parser}); !errors.Is(err, operations.ErrInvalid) {
		t.Fatal("typed nil factory accepted", err)
	}
	var nilParse config.ParseFunc
	if _, err := operations.NewCollector(operations.CollectorOptions{Store: store, Sessions: c.Sessions, Parser: nilParse}); !errors.Is(err, operations.ErrInvalid) {
		t.Fatal("nil parser accepted", err)
	}
	var nilReader *onlyReader
	c.Sessions = &nilReaderFactory{reader: nilReader}
	if _, err := c.Collect(context.Background(), req); !errors.Is(err, operations.ErrInvalid) {
		t.Fatal("typed nil reader accepted", err)
	}
}
func TestCanceledOperationsPrecedeValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (operations.Collector{}).Collect(ctx, operations.CollectRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatal("collector validated canceled request", err)
	}
	if _, err := (operations.Designer{}).Design(ctx, "", nil); !errors.Is(err, context.Canceled) {
		t.Fatal("designer validated canceled request", err)
	}
}

func TestOperationConstructorsRejectTypedNilStoresAndInvalidOptions(t *testing.T) {
	c, store, _, _ := collectionFixture(t)
	var nilStore *snapshot.Store
	for _, options := range []operations.CollectorOptions{
		{Store: nilStore, Sessions: c.Sessions, Parser: c.Parser},
		{Store: store, Sessions: c.Sessions, Parser: c.Parser, Timeout: -time.Second},
	} {
		if _, err := operations.NewCollector(options); !errors.Is(err, operations.ErrInvalid) {
			t.Fatal("invalid collector dependencies accepted", err)
		}
	}
	for _, options := range []operations.DesignerOptions{
		{Store: nilStore}, {Store: store, Timeout: -time.Second}, {Store: store, MaxCandidates: -1},
	} {
		if _, err := operations.NewDesigner(options); !errors.Is(err, operations.ErrInvalid) {
			t.Fatal("invalid designer dependencies accepted", err)
		}
	}
}

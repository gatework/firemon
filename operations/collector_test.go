package operations_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
)

const panBase = "set zone inside network layer3 ethernet1/1\nset zone outside network layer3 ethernet1/2\nset network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24\nset network interface ethernet ethernet1/2 layer3 ip 198.51.100.1/24\n"

type captureDevice struct {
	capture                    deploy.Capture
	openErr, readErr, closeErr error
	opens, reads, closes       int
	onRead                     func(context.Context)
}

type cancellingManifest struct {
	operations.CaptureStore
	cancel context.CancelFunc
}

func (s cancellingManifest) Manifest(ctx context.Context) (snapshot.Manifest, error) {
	manifest, err := s.CaptureStore.Manifest(ctx)
	s.cancel()
	return manifest, err
}

func (d *captureDevice) Open(ctx context.Context, device string) (deploy.Session, error) {
	d.opens++
	if _, ok := ctx.Deadline(); !ok || device == "" {
		return nil, errors.New("missing device or operation deadline")
	}
	if d.openErr != nil {
		return nil, d.openErr
	}
	return d, nil
}
func (d *captureDevice) Read(ctx context.Context, view deploy.View) (deploy.Capture, error) {
	d.reads++
	if view != deploy.Running {
		return deploy.Capture{}, errors.New("collection must read running configuration")
	}
	if d.onRead != nil {
		d.onRead(ctx)
	}
	return d.capture, d.readErr
}
func (*captureDevice) Execute(context.Context, []string, deploy.ReceiptFunc) (deploy.Outcome, error) {
	panic("collector attempted device writes")
}
func (*captureDevice) Save(context.Context, deploy.ReceiptFunc) (deploy.Outcome, error) {
	panic("collector attempted persistence")
}
func (*captureDevice) BeginConfiguration(context.Context, string) error {
	panic("collector attempted candidate mutation")
}
func (*captureDevice) EndConfiguration(context.Context, string) error {
	panic("collector attempted candidate mutation")
}
func (d *captureDevice) Close() error {
	d.closes++
	return d.closeErr
}

func parseNative(t *testing.T, raw string, metadata fm.Metadata) *fm.Firewall {
	t.Helper()
	fw, err := (vendors.Parser{}).Parse(context.Background(), config.Source{Text: raw, Complete: true}, metadata)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func collectionFixture(t *testing.T) (operations.Collector, *snapshot.Store, *captureDevice, operations.CollectRequest) {
	t.Helper()
	store, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	metadata := fm.Metadata{Device: "fw", Vendor: "paloalto"}
	base := parseNative(t, panBase, metadata)
	pub, err := store.Publish(context.Background(), base, snapshot.PublishOptions{PublicationID: "baseline"})
	if err != nil {
		t.Fatal(err)
	}
	device := &captureDevice{capture: deploy.Capture{Source: config.Source{Text: panBase + "set address captured ip-netmask 203.0.113.1/32\n", Complete: true}, Metadata: metadata}}
	collector := operations.Collector{Store: store, Sessions: device, Parser: vendors.Parser{}}
	return collector, store, device, operations.CollectRequest{Device: "fw", Expected: pub.Revision, PublicationID: "capture"}
}

func TestCollectorPublishesRunningCaptureAndClosesSession(t *testing.T) {
	c, store, device, req := collectionFixture(t)
	result, err := c.Collect(context.Background(), req)
	if err != nil || !result.Complete || result.Revision == "" || device.opens != 1 || device.reads != 1 || device.closes != 1 {
		t.Fatal("collection did not complete and close", result, err, device)
	}
	fw, head, err := store.Current(context.Background(), req.Device)
	if err != nil || head.Revision != result.Revision || fw.Address("captured") == nil || fw.Export().Raw != device.capture.Source.Text {
		t.Fatal("published graph lost native evidence", head, err)
	}
}

func TestCollectorRetainsIncompleteEvidenceAndInvalidatesOldCurrent(t *testing.T) {
	for _, failure := range []string{"partial capture", "read failure", "fatal parser", "nil parser graph", "parser lost completeness"} {
		t.Run(failure, func(t *testing.T) {
			c, store, device, req := collectionFixture(t)
			secretErr := errors.New("synthetic password marker: do-not-persist-this-error")
			switch failure {
			case "partial capture":
				device.capture.Source.Complete = false
			case "read failure":
				device.readErr = secretErr
			case "fatal parser":
				c.Parser = deploy.ParseFunc(func(context.Context, config.Source, fm.Metadata) (*fm.Firewall, error) { return nil, secretErr })
			case "nil parser graph":
				c.Parser = deploy.ParseFunc(func(context.Context, config.Source, fm.Metadata) (*fm.Firewall, error) { return nil, nil })
			case "parser lost completeness":
				device.capture.Source.Complete = false
				c.Parser = deploy.ParseFunc(func(ctx context.Context, source config.Source, m fm.Metadata) (*fm.Firewall, error) {
					source.Complete = true
					return (vendors.Parser{}).Parse(ctx, source, m)
				})
			}
			result, err := c.Collect(context.Background(), req)
			if !errors.Is(err, operations.ErrIncomplete) || result.Complete || result.Revision == "" || device.closes != 1 {
				t.Fatal("incomplete capture was discarded or made complete", result, err)
			}
			if _, _, err := store.Current(context.Background(), req.Device); !errors.Is(err, snapshot.ErrUnavailable) {
				t.Fatal("old current remained usable", err)
			}
			fw, err := store.Load(context.Background(), result.Revision)
			if err != nil || fw.Complete() || fw.Export().Raw != device.capture.Source.Text {
				t.Fatal("raw evidence was not retained", err)
			}
			for _, diagnostic := range fw.Diagnostics() {
				if strings.Contains(diagnostic.Message, "do-not-persist") {
					t.Fatal("transport/parser error leaked to diagnostics")
				}
			}
			retry, err := c.Collect(context.Background(), req)
			if !errors.Is(err, operations.ErrIncomplete) || retry != result || device.opens != 1 {
				t.Fatal("incomplete retry reopened device or changed result", retry, err)
			}
		})
	}
}

func TestCollectorPreflightRejectsStaleRevisionAndReservation(t *testing.T) {
	for _, failure := range []string{"stale", "reserved"} {
		t.Run(failure, func(t *testing.T) {
			c, store, device, req := collectionFixture(t)
			want := snapshot.ErrConflict
			if failure == "stale" {
				req.Expected = "stale"
			} else {
				if err := store.Reserve(context.Background(), req.Device, req.Expected, "deployment"); err != nil {
					t.Fatal(err)
				}
				want = snapshot.ErrReserved
			}
			if _, err := c.Collect(context.Background(), req); !errors.Is(err, want) || device.opens != 0 {
				t.Fatal("preflight opened device", err, device.opens)
			}
		})
	}
}

func TestCollectorOpenFailureCreatesNoEvidence(t *testing.T) {
	c, store, device, req := collectionFixture(t)
	device.openErr = errors.New("synthetic open failure")
	result, err := c.Collect(context.Background(), req)
	if !errors.Is(err, device.openErr) || result.Revision != "" || device.reads != 0 {
		t.Fatal(result, err)
	}
	_, head, err := store.Current(context.Background(), req.Device)
	if err != nil || head.Revision != req.Expected {
		t.Fatal("failed open invented live evidence", err)
	}
}

func TestCollectorRejectsWrongDeviceBeforeParsingOrPublishing(t *testing.T) {
	c, store, device, req := collectionFixture(t)
	device.capture.Metadata.Device = "another-device"
	c.Parser = deploy.ParseFunc(func(context.Context, config.Source, fm.Metadata) (*fm.Firewall, error) {
		t.Fatal("wrong device reached parser")
		return nil, nil
	})
	result, err := c.Collect(context.Background(), req)
	if !errors.Is(err, operations.ErrInvalid) || result.Revision != "" || device.closes != 1 {
		t.Fatal(result, err)
	}
	_, head, err := store.Current(context.Background(), req.Device)
	if err != nil || head.Revision != req.Expected {
		t.Fatal("wrong-device capture changed current", err)
	}
}

func TestCollectorRejectsParserIdentityOrRawSubstitution(t *testing.T) {
	for _, mismatch := range []string{"device", "vendor", "context", "software", "captured time", "raw"} {
		t.Run(mismatch, func(t *testing.T) {
			c, store, device, req := collectionFixture(t)
			device.capture.Metadata.Software = "11.0"
			device.capture.Metadata.CapturedAt = time.Date(2026, 10, 29, 1, 0, 0, 0, time.UTC)
			c.Parser = deploy.ParseFunc(func(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
				fw, err := (vendors.Parser{}).Parse(ctx, source, metadata)
				if err != nil {
					return nil, err
				}
				d := fw.Export()
				switch mismatch {
				case "device":
					d.Metadata.Device = "another"
				case "vendor":
					d.Metadata.Vendor = "asa"
				case "context":
					d.Metadata.Context = "another"
				case "software":
					d.Metadata.Software = "9.0"
				case "captured time":
					d.Metadata.CapturedAt = d.Metadata.CapturedAt.Add(time.Hour)
				case "raw":
					d.Raw += "altered"
					d.Metadata.SourceDigest = ""
				}
				return fm.Seal(d)
			})
			result, err := c.Collect(context.Background(), req)
			if !errors.Is(err, operations.ErrInvalid) || !errors.Is(err, operations.ErrIncomplete) || result.Complete {
				t.Fatal("parser substitution accepted", result, err)
			}
			if _, _, err := store.Current(context.Background(), req.Device); !errors.Is(err, snapshot.ErrUnavailable) {
				t.Fatal("parser substitution left stale current usable", err)
			}
		})
	}
}

func TestCollectorCancellationClosesAndRetainsPartialEvidence(t *testing.T) {
	c, store, device, req := collectionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	device.onRead = func(context.Context) { cancel() }
	device.readErr = context.Canceled
	result, err := c.Collect(ctx, req)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, operations.ErrIncomplete) || result.Complete || result.Revision == "" || device.closes != 1 {
		t.Fatal("cancellation lost partial evidence or session ownership", result, err)
	}
	if _, _, err := store.Current(context.Background(), req.Device); !errors.Is(err, snapshot.ErrUnavailable) {
		t.Fatal("cancelled capture left stale current", err)
	}
	device.opens = 0
	if _, err := c.Collect(ctx, req); !errors.Is(err, context.Canceled) || device.opens != 0 {
		t.Fatal("already-cancelled request reopened device", err)
	}
}

func TestCollectorRetryPreservesCancellationDuringManifestRead(t *testing.T) {
	c, store, device, req := collectionFixture(t)
	if _, err := c.Collect(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Store = cancellingManifest{CaptureStore: store, cancel: cancel}
	if result, err := c.Collect(ctx, req); !errors.Is(err, context.Canceled) || result.Revision != "" || device.opens != 1 {
		t.Fatal("known-publication retry lost cancellation", result, err)
	}
}

func TestCollectorTimeoutBoundsReadAndRetainsEvidence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, _, device, req := collectionFixture(t)
		c.Timeout = time.Minute
		device.onRead = func(ctx context.Context) { <-ctx.Done() }
		result, err := c.Collect(context.Background(), req)
		if !errors.Is(err, context.DeadlineExceeded) || result.Complete || result.Revision == "" || device.closes != 1 {
			t.Fatal("operation deadline was not enforced", result, err)
		}
	})
}

func TestCollectorRetryReturnsPriorPublicationEvenAfterAnotherCapture(t *testing.T) {
	c, _, device, req := collectionFixture(t)
	first, err := c.Collect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	device.capture.Source.Text += "set address later ip-netmask 203.0.113.2/32\n"
	if _, err := c.Collect(context.Background(), operations.CollectRequest{Device: req.Device, Expected: first.Revision, PublicationID: "later"}); err != nil {
		t.Fatal(err)
	}
	retry, err := c.Collect(context.Background(), req)
	if err != nil || retry != first || device.opens != 2 {
		t.Fatal("retry recaptured instead of returning known publication", retry, err)
	}
	for _, changed := range []operations.CollectRequest{
		{Device: "different", Expected: req.Expected, PublicationID: req.PublicationID},
		{Device: req.Device, Expected: first.Revision, PublicationID: req.PublicationID},
	} {
		if _, err := c.Collect(context.Background(), changed); !errors.Is(err, snapshot.ErrConflict) || device.opens != 2 {
			t.Fatal("conflicting retry reopened device", err)
		}
	}
}

func TestCollectorPublishCASDetectsChangeDuringRead(t *testing.T) {
	c, store, device, req := collectionFixture(t)
	device.onRead = func(ctx context.Context) {
		other := parseNative(t, panBase+"set address concurrent ip-netmask 203.0.113.5/32\n", device.capture.Metadata)
		if _, err := store.Publish(ctx, other, snapshot.PublishOptions{Expected: req.Expected, PublicationID: "concurrent", Live: true}); err != nil {
			t.Fatal(err)
		}
	}
	if result, err := c.Collect(context.Background(), req); !errors.Is(err, snapshot.ErrConflict) || result.Revision != "" || device.closes != 1 {
		t.Fatal("collection overwrote a concurrent publication", result, err)
	}
}

func TestCollectorFatalNativeParseRetainsSelectedContextAndRaw(t *testing.T) {
	store, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	metadata := fm.Metadata{Device: "tenant-device", Vendor: "fortinet", Context: "tenant"}
	base := parseNative(t, "config firewall address\nedit host\nset subnet 192.0.2.1 255.255.255.255\nnext\nend\n", metadata)
	pub, err := store.Publish(context.Background(), base, snapshot.PublishOptions{PublicationID: "base"})
	if err != nil {
		t.Fatal(err)
	}
	raw := "config firewall address\nedit unfinished\nset subnet 192.0.2.2 255.255.255.255\n"
	device := &captureDevice{capture: deploy.Capture{Source: config.Source{Text: raw, Complete: true}, Metadata: metadata}}
	c := operations.Collector{Store: store, Sessions: device, Parser: vendors.Parser{}}
	result, err := c.Collect(context.Background(), operations.CollectRequest{Device: metadata.Device, Expected: pub.Revision, PublicationID: "bad-native"})
	if !errors.Is(err, config.ErrSource) || !errors.Is(err, operations.ErrIncomplete) || result.Complete || result.Revision == "" {
		t.Fatal("fatal native failure was not published conservatively", result, err)
	}
	fw, err := store.Load(context.Background(), result.Revision)
	if err != nil || fw.Metadata().Context != "tenant" || fw.Export().Raw != raw || fw.Complete() {
		t.Fatal("selected context or failed native text lost", err)
	}
	if _, _, err := store.Current(context.Background(), metadata.Device); !errors.Is(err, snapshot.ErrUnavailable) {
		t.Fatal("old selected context is still current", err)
	}
}

func TestCollectorReturnsCloseErrorWithPublishedEvidence(t *testing.T) {
	c, store, device, req := collectionFixture(t)
	device.closeErr = errors.New("synthetic close failure")
	result, err := c.Collect(context.Background(), req)
	if !errors.Is(err, device.closeErr) || !result.Complete || result.Revision == "" || device.closes != 1 {
		t.Fatal("close error or completed capture was discarded", result, err)
	}
	_, head, err := store.Current(context.Background(), req.Device)
	if err != nil || head.Revision != result.Revision {
		t.Fatal("close transport failure lost independently complete evidence", err)
	}
}

func TestCollectorCannotReplaceReservedDeviceWhenReservationAppearsDuringRead(t *testing.T) {
	c, store, device, req := collectionFixture(t)
	device.onRead = func(ctx context.Context) {
		if err := store.Reserve(ctx, req.Device, req.Expected, "deployment"); err != nil {
			t.Fatal(err)
		}
	}
	if result, err := c.Collect(context.Background(), req); !errors.Is(err, snapshot.ErrReserved) || result.Revision != "" || device.closes != 1 {
		t.Fatal("collection stole deployment ownership", result, err)
	}
}

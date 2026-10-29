package operations_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
)

func requestTraffic(t *testing.T, source, destination string, sourcePort uint16) flow.Traffic {
	t.Helper()
	src, _ := flow.PrefixRange(netip.MustParsePrefix(source))
	dst, _ := flow.PrefixRange(netip.MustParsePrefix(destination))
	traffic, err := flow.NewTraffic(8, flow.Box{Source: src, Destination: dst,
		Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: sourcePort, High: sourcePort},
		DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255},
	})
	if err != nil {
		t.Fatal(err)
	}
	return traffic
}

func TestDesignerUsesCurrentRevisionAndNativeRendererReadback(t *testing.T) {
	_, store, _, req := collectionFixture(t)
	designer := operations.Designer{Store: store, Engine: policy.Engine{}}
	requests := []policy.Request{{Traffic: requestTraffic(t, "192.0.2.10/32", "198.51.100.10/32", 1024), FromZone: "inside", ToZone: "outside"}}
	result, err := designer.Design(context.Background(), req.Device, requests)
	if err != nil || result.Revision != req.Expected || result.Plan == nil || len(result.Plan.Commands()) == 0 {
		t.Fatal(result, err)
	}
	raw := panBase
	for _, command := range result.Plan.Commands() {
		if strings.HasPrefix(command, "set ") {
			raw += command + "\n"
		}
	}
	readback := parseNative(t, raw, fm.Metadata{Device: req.Device, Vendor: "paloalto"})
	if _, err := result.Plan.Verify(context.Background(), readback); err != nil {
		t.Fatal("native renderer and independent parser disagree", err)
	}
}

func TestDesignerDefaultsSelectedContextWithoutMutatingRequests(t *testing.T) {
	store, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../vendors/fortinet/testdata/basic.conf")
	if err != nil {
		t.Fatal(err)
	}
	fw := parseNative(t, strings.ReplaceAll(string(raw), `"root"`, `"tenant"`), fm.Metadata{Device: "tenant-device", Vendor: "fortinet", Context: "tenant"})
	pub, err := store.Publish(context.Background(), fw, snapshot.PublishOptions{PublicationID: "tenant"})
	if err != nil {
		t.Fatal(err)
	}
	requests := []policy.Request{{Traffic: requestTraffic(t, "192.0.2.10/32", "203.0.113.10/32", 1000), FromZone: "inside", ToZone: "wan1"}}
	result, err := (operations.Designer{Store: store}).Design(context.Background(), "tenant-device", requests)
	if err != nil || result.Revision != pub.Revision || len(result.Plan.Commands()) != 0 || requests[0].Scope != "" {
		t.Fatal("selected context was lost or caller input mutated", result, err)
	}
}

func TestDesignerRejectsReservedIncompleteAndMissingCurrent(t *testing.T) {
	for _, state := range []string{"reserved", "incomplete", "missing"} {
		t.Run(state, func(t *testing.T) {
			c, store, device, req := collectionFixture(t)
			want := snapshot.ErrUnavailable
			switch state {
			case "reserved":
				if err := store.Reserve(context.Background(), req.Device, req.Expected, "pending"); err != nil {
					t.Fatal(err)
				}
			case "incomplete":
				device.capture.Source.Complete = false
				if _, err := c.Collect(context.Background(), req); !errors.Is(err, operations.ErrIncomplete) {
					t.Fatal(err)
				}
			case "missing":
				req.Device = "missing"
				want = snapshot.ErrNotFound
			}
			if _, err := (operations.Designer{Store: store}).Design(context.Background(), req.Device, []policy.Request{{}}); !errors.Is(err, want) {
				t.Fatal("unavailable current became design input", err)
			}
		})
	}
}

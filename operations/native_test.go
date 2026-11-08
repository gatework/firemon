package operations_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"slices"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

type nativeTestRenderer struct{}

func (nativeTestRenderer) RenderNative(ctx context.Context, before, after *fm.Firewall, c plan.NativeChanges) ([]string, error) {
	if err := plan.ValidateNativeChanges(ctx, before, after, c); err != nil {
		return nil, err
	}
	return []string{"synthetic typed nat"}, nil
}
func TestBusinessNativeJSONProducesJointPlan(t *testing.T) {
	_, store, _, req := collectionFixture(t)
	traffic := requestTraffic(t, "192.0.2.10/32", "198.51.100.10/32", 1024)
	box := traffic.Regions()[0]
	m := fm.Match{Sources: []fm.AddressRef{{Kind: fm.AddressObject, ID: "original"}}, Destinations: []fm.AddressRef{{Kind: fm.AddressObject, ID: "target"}}, Services: []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "service"}}, FromZones: []fm.ID{"inside"}, ToZones: []fm.ID{"outside"}}
	adds := plan.NativeAdditions{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "original"}, Ranges: []flow.AddressRange{box.Source}}, {Object: fm.Object{ID: "target"}, Ranges: []flow.AddressRange{box.Destination}}}, Services: []fm.ServiceRecord{{Object: fm.Object{ID: "service"}, Terms: []fm.ServiceTerm{{Protocol: box.Protocol, SourcePort: box.SourcePort, DestinationPort: box.DestinationPort, ICMPType: box.ICMPType, ICMPCode: box.ICMPCode}}}}, StaticNATs: []fm.StaticNATRecord{{Object: fm.Object{ID: "fixed"}, Match: m, Source: []fm.Mapping{{Original: box.Source, Translated: box.Destination, Mode: fm.Constant}}}}}
	target := operations.TargetDocument{Device: req.Device, Policy: operations.PolicyDocument{FromZone: "inside", ToZone: "outside"}, Packet: true, VRF: ""}
	document := operations.RequestDocument{Version: 1, Requests: []operations.AccessDocument{{Traffic: traffic.Regions(), Targets: []operations.TargetDocument{target}, Native: &operations.NativeDocument{Additions: adds, NAT: []operations.NATIntentDocument{{Request: operations.PolicyDocument{Traffic: traffic.Regions(), FromZone: "inside", ToZone: "outside"}, Steps: []policy.NATStep{{Kind: fm.StaticNATObject, ID: "fixed"}}}}}}}}
	document.Requests[0].Sources = []string{"ticket", "ticket", "native"}
	raw, _ := json.Marshal(document)
	input, err := operations.DecodeBatchRequest(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	d, err := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store, NativeRenderer: nativeTestRenderer{}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := d.Design(context.Background(), input)
	if err != nil || len(result.Devices) != 1 || result.Devices[0].Batch.Plan == nil {
		t.Fatal(result, err)
	}
	p := result.Devices[0].Batch.Plan
	if p.NATProof() == nil || p.After().StaticNAT("fixed") == nil || len(p.NativeInputs()) != 1 || len(p.PacketProofs()) != 1 {
		t.Fatal("native intent lost")
	}
	if !slices.Equal(p.NativeInputs()[0].Sources, document.Requests[0].Sources) || len(result.Inputs[0].Outcomes[0].Sources) != 0 {
		t.Fatal("native business sources changed or leaked into target sources", result)
	}
	if _, err := p.Verify(context.Background(), p.After()); err != nil {
		t.Fatal(err)
	}
}

func TestBusinessNativeIngressBoundsNestedInputBeforeSnapshotRead(t *testing.T) {
	for _, field := range []string{"ranges", "terms", "match", "sources", "packet"} {
		t.Run(field, func(t *testing.T) {
			_, store, _, req := collectionFixture(t)
			counted := &countedBatchStore{Store: store}
			d, err := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: counted, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 64}}})
			if err != nil {
				t.Fatal(err)
			}
			a := operations.AccessRequest{Traffic: requestTraffic(t, "192.0.2.10/32", "198.51.100.10/32", 1024), Targets: []operations.AccessTarget{{Device: req.Device, Request: policy.Request{FromZone: "inside", ToZone: "outside"}, Packet: true}}, Native: &operations.NativeEffects{}}
			switch field {
			case "ranges":
				a.Native.Additions.Addresses = []fm.AddressRecord{{Ranges: make([]flow.AddressRange, 65)}}
			case "terms":
				a.Native.Additions.Services = []fm.ServiceRecord{{Terms: make([]fm.ServiceTerm, 65)}}
			case "match":
				a.Native.Additions.StaticNATs = []fm.StaticNATRecord{{Match: fm.Match{Applications: make([]string, 65)}}}
			case "sources":
				a.Sources = make([]string, 65)
			case "packet":
				var regions []flow.TrafficRegion
				box := a.Traffic.Regions()[0]
				for i := range 65 {
					box.SourcePort = flow.Interval{Low: uint16(i * 2), High: uint16(i * 2)}
					regions = append(regions, box)
				}
				a.Traffic, err = flow.NewTraffic(100, regions...)
				if err != nil {
					t.Fatal(err)
				}
			}
			report, err := d.Design(context.Background(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{a}})
			if !errors.Is(err, policy.ErrBudget) || counted.manifests != 0 || counted.loads != 0 || len(report.Devices) != 0 {
				t.Fatalf("input work preceded preflight: err=%v reads=%d/%d", err, counted.manifests, counted.loads)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err = d.Design(ctx, operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{a}})
			if !errors.Is(err, context.Canceled) || counted.manifests != 0 {
				t.Fatal(err, counted.manifests)
			}
		})
	}
}

type nativeCancelCheckpoint struct {
	context.Context
	checks, limit int
}

func (c *nativeCancelCheckpoint) Err() error {
	c.checks++
	if c.checks >= c.limit {
		return context.Canceled
	}
	return nil
}
func TestBusinessNativeIngressCancellationAndAllocationBeforeSnapshot(t *testing.T) {
	_, store, _, req := collectionFixture(t)
	counted := &countedBatchStore{Store: store}
	d, err := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: counted, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 100}}})
	if err != nil {
		t.Fatal(err)
	}
	a := operations.AccessRequest{Traffic: requestTraffic(t, "192.0.2.10/32", "198.51.100.10/32", 1024), Targets: []operations.AccessTarget{{Device: req.Device, Request: policy.Request{FromZone: "inside", ToZone: "outside"}}}, Native: &operations.NativeEffects{Additions: plan.NativeAdditions{Addresses: make([]fm.AddressRecord, 8)}}}
	ctx := &nativeCancelCheckpoint{Context: context.Background(), limit: 20}
	_, err = d.Design(ctx, operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{a}})
	if !errors.Is(err, context.Canceled) || counted.manifests != 0 {
		t.Fatal(err, counted.manifests)
	}
	a.Native.Additions.Addresses = []fm.AddressRecord{{Ranges: make([]flow.AddressRange, 8192)}}
	input := operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{a}}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 5 {
		_, err = d.Design(context.Background(), input)
		if !errors.Is(err, policy.ErrBudget) || counted.manifests != 0 {
			t.Fatal(err, counted.manifests)
		}
	}
	runtime.ReadMemStats(&after)
	if bytes := (after.TotalAlloc - before.TotalAlloc) / 5; bytes > 64<<10 {
		t.Fatalf("business rejection cloned oversized nested ranges: %d bytes/call", bytes)
	}
}

func TestBusinessNativeIngressSharesCapacityAcrossInputs(t *testing.T) {
	_, store, _, req := collectionFixture(t)
	counted := &countedBatchStore{Store: store}
	d, err := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: counted, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 64}}})
	if err != nil {
		t.Fatal(err)
	}
	a := operations.AccessRequest{Traffic: requestTraffic(t, "192.0.2.10/32", "198.51.100.10/32", 1024), Targets: []operations.AccessTarget{{Device: req.Device, Request: policy.Request{FromZone: "inside", ToZone: "outside"}}}, Native: &operations.NativeEffects{Additions: plan.NativeAdditions{Addresses: []fm.AddressRecord{{Ranges: make([]flow.AddressRange, 40)}}}}}
	_, err = d.Design(context.Background(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{a, a}})
	if !errors.Is(err, policy.ErrBudget) || counted.manifests != 0 {
		t.Fatal("business input budget reset", err, counted.manifests)
	}
}

func TestBusinessFiniteIntentJSONWithoutNAT(t *testing.T) {
	traffic := requestTraffic(t, "192.0.2.10/32", "198.51.100.10/32", 443)
	document := operations.RequestDocument{Version: 1, Requests: []operations.AccessDocument{{Traffic: traffic.Regions(), Targets: []operations.TargetDocument{{Device: "fw", Policy: operations.PolicyDocument{FromZone: "inside", ToZone: "outside"}}}, Native: &operations.NativeDocument{Lifetime: &plan.ScheduleIntent{Schedule: "one-time"}, Additions: plan.NativeAdditions{Schedules: []fm.ScheduleRecord{{Object: fm.Object{ID: "one-time"}}}}}}}}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	request, err := operations.DecodeBatchRequest(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if request.Requests[0].Native.Lifetime == nil || request.Requests[0].Native.Lifetime.Schedule != "one-time" || len(request.Requests[0].Native.Additions.Schedules) != 1 {
		t.Fatal("finite intent lost")
	}
	// Decoding is syntax-only. An unbound clock cannot become an executable plan.
	_, store, _, _ := collectionFixture(t)
	designer, err := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store, NativeRenderer: nativeTestRenderer{}})
	if err != nil {
		t.Fatal(err)
	}
	report, err := designer.Design(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range report.Devices {
		if device.Batch.Plan != nil {
			t.Fatal("unbound finite intent became executable")
		}
	}
}

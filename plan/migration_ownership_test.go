package plan_test

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors"
)

type migrationDriver struct {
	plan.Renderer
	compiler   plan.MigrationNATCompiler
	native     plan.NativeRenderer
	compiled   plan.NativeChanges
	rendered   plan.NativeChanges
	commands   []string
	compile    func(*plan.NativeChanges)
	compileErr error
	render     func()
}

func newMigrationDriver(t *testing.T) *migrationDriver {
	t.Helper()
	renderer, err := vendors.Renderer("paloalto")
	if err != nil {
		t.Fatal(err)
	}
	return &migrationDriver{
		Renderer: renderer,
		compiler: renderer.(plan.MigrationNATCompiler),
		native:   renderer.(plan.NativeRenderer),
	}
}

func (d *migrationDriver) CompileMigrationNAT(
	ctx context.Context,
	source, target *fm.Firewall,
	draft plan.NativeMigrationDraft,
) (plan.NativeChanges, error) {
	changes, err := d.compiler.CompileMigrationNAT(ctx, source, target, draft)
	if err != nil {
		return plan.NativeChanges{}, err
	}
	if d.compile != nil {
		d.compile(&changes)
	}
	d.compiled = changes
	return changes, d.compileErr
}

func (d *migrationDriver) RenderNative(
	ctx context.Context,
	before, after *fm.Firewall,
	changes plan.NativeChanges,
) ([]string, error) {
	d.rendered = changes
	commands, err := d.native.RenderNative(ctx, before, after, changes)
	d.commands = commands
	if d.render != nil {
		d.render()
	}
	return commands, err
}

func migrationGraphs(t *testing.T) (*fm.Firewall, *fm.Firewall, plan.MigrationInput) {
	t.Helper()
	d := baseline(t).Export()
	d.Metadata = fm.Metadata{Device: "source", Vendor: "paloalto", Software: "10.2.0"}
	d.Zones = []fm.ZoneRecord{
		{Object: fm.Object{ID: "inside", Name: "inside"}},
		{Object: fm.Object{ID: "outside", Name: "outside"}},
	}
	d.Interfaces = []fm.InterfaceRecord{
		{Object: fm.Object{ID: "ethernet1/1", Name: "ethernet1/1"}, Zone: "inside", Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.254/24")}},
		{Object: fm.Object{ID: "ethernet1/2", Name: "ethernet1/2"}, Zone: "outside", Addresses: []netip.Prefix{netip.MustParsePrefix("198.51.100.254/24")}},
	}
	d.Routes = []fm.RouteRecord{
		{Object: fm.Object{ID: "inside-route"}, Destination: netip.MustParsePrefix("192.0.2.0/24"), Interface: "ethernet1/1"},
		{Object: fm.Object{ID: "outside-route"}, Destination: netip.MustParsePrefix("198.51.100.0/24"), Interface: "ethernet1/2"},
	}
	rule := &d.Rules[0]
	rule.Name = "allow"
	rule.LogStart, rule.LogEnd = fm.Irrelevant, fm.Irrelevant
	rule.Match.AnyFromZone, rule.Match.AnyToZone = false, false
	rule.Match.FromZones, rule.Match.ToZones = []fm.ID{"inside"}, []fm.ID{"outside"}
	d.NATPools = []fm.NATPoolRecord{{Object: fm.Object{ID: "pool", Name: "pool"}, Ranges: []flow.AddressRange{addressRange("203.0.113.100/30")}}}
	d.DynamicNATs = []fm.DynamicNATRecord{{
		Object: fm.Object{ID: "translate", Name: "translate"}, Match: rule.Match,
		SourceMode: fm.DynamicIPPort, DestinationMode: fm.NoTranslation, SourcePool: "pool",
	}}
	source, err := fm.Seal(d)
	if err != nil || !source.Complete() {
		t.Fatalf("source: %v", err)
	}
	d.Metadata.Device = "target"
	d.Rules, d.Addresses, d.Services, d.DynamicNATs, d.NATPools = nil, nil, nil, nil, nil
	target, err := fm.Seal(d)
	if err != nil || !target.Complete() {
		t.Fatalf("target: %v", err)
	}
	coordinate := plan.MigrationContext{Chain: fm.PolicyChain{RuleSet: "security"}, FromZone: "inside", ToZone: "outside"}
	input := plan.MigrationInput{
		From:        time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		Contexts:    []plan.MigrationContextMapping{{Source: coordinate, Target: coordinate}},
		DynamicNATs: []fm.ID{"translate"},
		Interfaces: []plan.MigrationInterfaceMapping{
			{Source: "ethernet1/1", Target: "ethernet1/1"},
			{Source: "ethernet1/2", Target: "ethernet1/2"},
		},
		VRFs: []plan.MigrationVRFMapping{{Source: "", Target: ""}},
	}
	return source, target, input
}

func TestMigrationOwnsCompilerAndRendererResults(t *testing.T) {
	source, target, input := migrationGraphs(t)
	for _, owner := range []string{"compiler", "renderer"} {
		t.Run(owner, func(t *testing.T) {
			driver := newMigrationDriver(t)
			result, err := (plan.Planner{Renderer: driver}).Migrate(t.Context(), source, target, input)
			if err != nil {
				t.Fatal(err)
			}
			changes, native, commands, digest := result.Changes(), result.NativeChanges(), result.Commands(), result.Digest()
			retained := driver.compiled
			if owner == "renderer" {
				retained = driver.rendered
				driver.commands[0] = "unreviewed command"
			}
			retained.Rules[0].Sources[0].ID = "unrelated-address"
			retained.Additions.NATPools[0].Ranges[0] = addressRange("203.0.113.200/32")
			if !reflect.DeepEqual(result.Changes(), changes) || !reflect.DeepEqual(result.NativeChanges(), native) ||
				!reflect.DeepEqual(result.Commands(), commands) || result.Digest() != digest {
				t.Fatal("callback retained mutable plan storage")
			}
			if err := plan.ValidateNativeChanges(t.Context(), result.Before(), result.After(), result.NativeChanges()); err != nil {
				t.Fatal("plan no longer describes its proven graph:", err)
			}
		})
	}
}

func TestMigrationRejectsCallbackCancellation(t *testing.T) {
	source, target, input := migrationGraphs(t)
	for _, callback := range []string{"compiler", "renderer"} {
		t.Run(callback, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			driver := newMigrationDriver(t)
			if callback == "compiler" {
				driver.compile = func(*plan.NativeChanges) { cancel() }
				driver.compileErr = plan.ErrRender
			} else {
				driver.render = cancel
			}
			result, err := (plan.Planner{Renderer: driver}).Migrate(ctx, source, target, input)
			if result != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled %s: plan=%v, err=%v", callback, result != nil, err)
			}
		})
	}
}

func TestMigrationRejectsOversizedCompilerChanges(t *testing.T) {
	source, target, input := migrationGraphs(t)
	driver := newMigrationDriver(t)
	driver.compile = func(changes *plan.NativeChanges) {
		changes.Rules[0].Sources = make([]fm.AddressRef, 100001)
	}
	result, err := (plan.Planner{Renderer: driver}).Migrate(t.Context(), source, target, input)
	if result != nil || !errors.Is(err, policy.ErrBudget) {
		t.Fatalf("compiler changes escaped budget: plan=%v, err=%v", result != nil, err)
	}
}

func TestMigrationUsesRendererFallbackForTypedNilNativeRenderer(t *testing.T) {
	source, target, input := migrationGraphs(t)
	var absent *migrationDriver
	driver := newMigrationDriver(t)
	defer func() {
		if value := recover(); value != nil {
			t.Errorf("typed-nil renderer panicked: %v", value)
		}
	}()
	result, err := (plan.Planner{Renderer: driver, NativeRenderer: absent}).Migrate(t.Context(), source, target, input)
	if err != nil || result == nil || len(driver.commands) == 0 {
		t.Fatalf("valid native fallback was not used: %v", err)
	}
}

func TestMigrationRejectsTypedNilCompiler(t *testing.T) {
	source, target, input := migrationGraphs(t)
	var absent *migrationDriver
	result, err := (plan.Planner{Renderer: absent}).Migrate(t.Context(), source, target, input)
	if result != nil || !errors.Is(err, plan.ErrInvalid) {
		t.Fatalf("typed-nil compiler: plan=%v, err=%v", result != nil, err)
	}
}

func TestMigrationOwnsScheduledRendererResults(t *testing.T) {
	source, target, input := migrationGraphs(t)
	d := source.Export()
	d.DynamicNATs, d.NATPools = nil, nil
	d.Schedules = []fm.ScheduleRecord{{
		Object: fm.Object{ID: "window", Name: "window"}, Timezone: "UTC", Calendar: fm.CalendarCivil,
		Windows: []fm.TimeWindow{{Start: input.From, End: input.From.Add(time.Hour)}},
	}}
	d.Rules[0].Match.Schedule = "window"
	var err error
	source, err = fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	d = target.Export()
	d.Raw, d.Metadata.CapturedAt = "synthetic target capture", input.From
	target, err = fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	m := target.Metadata()
	input.DynamicNATs = nil
	input.Clock = &fm.ScheduleClock{
		CapturedAt: m.CapturedAt, Device: m.Device, Vendor: m.Vendor, Software: m.Software,
		SourceDigest: m.SourceDigest, Timezone: "UTC", Reference: "synthetic clock evidence",
		EndBoundary: "exclusive", TickSeconds: 60, Calendar: fm.CalendarCivil,
	}
	driver := newMigrationDriver(t)
	result, err := (plan.Planner{Renderer: driver}).Migrate(t.Context(), source, target, input)
	if err != nil {
		t.Fatal(err)
	}
	native, commands, digest := result.NativeChanges(), result.Commands(), result.Digest()
	driver.rendered.Additions.Schedules[0].Windows[0].End = input.From.Add(2 * time.Hour)
	driver.rendered.Clock.Timezone = "Asia/Hong_Kong"
	driver.commands[0] = "unreviewed command"
	if !reflect.DeepEqual(result.NativeChanges(), native) || !reflect.DeepEqual(result.Commands(), commands) || result.Digest() != digest {
		t.Fatal("renderer retained mutable schedule plan storage")
	}
}

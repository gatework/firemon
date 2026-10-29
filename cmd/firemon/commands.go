package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
)

func output(w io.Writer, v any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}
func execute(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: firemon import|inspect|query|nat|plan [flags]")
	}
	switch args[0] {
	case "import":
		return importConfig(ctx, args[1:], out)
	case "inspect", "query", "nat", "plan":
		return inspectOrQuery(ctx, args[0], args[1:], out)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
func flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}
func importConfig(ctx context.Context, args []string, out io.Writer) error {
	fs := flags("import")
	root := fs.String("store", "", "snapshot directory")
	device := fs.String("device", "", "device identifier")
	vendor := fs.String("vendor", "", "native vendor")
	vdom := fs.String("vdom", "", "Fortinet VDOM (default root)")
	file := fs.String("file", "", "configuration path")
	complete := fs.Bool("complete", false, "capture is known complete")
	publication := fs.String("publication", "", "idempotency identifier")
	expected := fs.String("expected", "", "expected current revision")
	software := fs.String("software", "", "captured software version")
	capturedAt := fs.String("captured-at", "", "known capture time, RFC3339")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *root == "" || *device == "" || *file == "" || *publication == "" {
		return errors.New("store, device, file and publication are required")
	}
	if *vdom != "" && *vendor != "fortinet" {
		return errors.New("vdom applies only to Fortinet imports")
	}
	input, err := os.Open(*file)
	if err != nil {
		return err
	}
	defer input.Close()
	raw, err := io.ReadAll(io.LimitReader(input, (16<<20)+1))
	if err != nil {
		return err
	}
	if len(raw) > 16<<20 {
		return config.ErrSource
	}
	meta := fm.Metadata{Device: *device, Vendor: *vendor, Context: *vdom, Software: *software}
	if *capturedAt != "" {
		meta.CapturedAt, err = time.Parse(time.RFC3339, *capturedAt)
		if err != nil {
			return err
		}
	}
	fw, err := (vendors.Parser{}).Parse(ctx, config.Source{Text: string(raw), Complete: *complete}, meta)
	if err != nil {
		return err
	}
	store, err := snapshot.Open(*root)
	if err != nil {
		return err
	}
	published, err := store.Publish(ctx, fw, snapshot.PublishOptions{Expected: *expected, PublicationID: *publication})
	if err != nil {
		return err
	}
	return output(out, struct {
		Revision    string          `json:"revision"`
		Generation  uint64          `json:"generation"`
		Complete    bool            `json:"complete"`
		Archived    bool            `json:"archived"`
		Diagnostics []fm.Diagnostic `json:"diagnostics"`
	}{published.Revision, published.Generation, fw.Complete(), published.Archived, fw.Diagnostics()})
}
func inspectOrQuery(ctx context.Context, command string, args []string, out io.Writer) error {
	fs := flags(command)
	root := fs.String("store", "", "snapshot directory")
	device := fs.String("device", "", "device identifier")
	revision := fs.String("revision", "", "historical revision (inspect only)")
	source := fs.String("source", "", "source CIDR")
	destination := fs.String("destination", "", "destination CIDR")
	service := fs.String("service", "", "protocol/port, e.g. tcp/443")
	scope := fs.String("scope", "", "VRF/vsys context")
	ruleset := fs.String("ruleset", "security", "native rule set")
	from := fs.String("from-zone", "", "ingress zone")
	to := fs.String("to-zone", "", "egress zone")
	at := fs.String("at", "", "evaluation time RFC3339")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *root == "" || (*device == "" && *revision == "") {
		return errors.New("store and device are required")
	}
	if *revision != "" && command != "inspect" {
		return errors.New("historical revisions are inspect-only")
	}
	store, err := snapshot.Open(*root)
	if err != nil {
		return err
	}
	var fw *fm.Firewall
	var head snapshot.Head
	if *revision != "" {
		fw, err = store.Load(ctx, *revision)
		head.Revision = *revision
	} else {
		fw, head, err = store.Current(ctx, *device)
	}
	if err != nil {
		return err
	}
	if command == "inspect" {
		return output(out, struct {
			Device      string          `json:"device"`
			Context     string          `json:"context,omitempty"`
			Revision    string          `json:"revision"`
			Complete    bool            `json:"complete"`
			Interfaces  int             `json:"interfaces"`
			Routes      int             `json:"routes"`
			Rules       int             `json:"rules"`
			StaticNATs  int             `json:"static_nats"`
			DynamicNATs int             `json:"dynamic_nats"`
			Diagnostics []fm.Diagnostic `json:"diagnostics"`
		}{fw.Metadata().Device, fw.Metadata().Context, head.Revision, fw.Complete(), len(fw.Interfaces()), len(fw.Routes()), len(fw.Rules()), len(fw.StaticNATs()), len(fw.DynamicNATs()), fw.Diagnostics()})
	}
	traffic, err := requestTraffic(*source, *destination, *service)
	if err != nil {
		return err
	}
	q := policy.Request{Traffic: traffic, Scope: *scope, RuleSet: *ruleset, FromZone: fm.ID(*from), ToZone: fm.ID(*to)}
	if q.Scope == "" {
		q.Scope = fw.Metadata().Context
	}
	if *at != "" {
		q.At, err = time.Parse(time.RFC3339, *at)
		if err != nil {
			return err
		}
	}
	switch command {
	case "query":
		result, err := (policy.Engine{}).Query(ctx, fw, q)
		if err != nil {
			return err
		}
		return output(out, struct {
			Complete bool                            `json:"complete"`
			Coverage map[string][]flow.TrafficRegion `json:"coverage"`
		}{Complete: result.Complete, Coverage: map[string][]flow.TrafficRegion{"allowed": result.Allowed.Regions(), "denied": result.Denied.Regions(), "unknown": result.Unknown.Regions(), "unmatched": result.Unmatched.Regions()}})
	case "nat":
		result, err := (policy.Engine{}).QueryNAT(ctx, fw, q)
		if err != nil {
			return err
		}
		type relation struct {
			Kind                      fm.Kind
			ID                        fm.ID
			Steps                     []policy.NATStep
			Original, Translated      []flow.TrafficRegion
			Exact, PossibleAllocation bool
		}
		rows := make([]relation, 0, len(result.Relations))
		for _, r := range result.Relations {
			rows = append(rows, relation{r.Kind, r.ID, r.Steps, r.Original.Regions(), r.Translated.Regions(), r.Exact, r.PossibleAllocation})
		}
		return output(out, struct {
			Complete           bool
			Relations          []relation
			Unknown, Unmatched []flow.TrafficRegion
		}{result.Complete, rows, result.Unknown.Regions(), result.Unmatched.Regions()})
	case "plan":
		renderer, err := vendors.Renderer(fw.Metadata().Vendor)
		if err != nil {
			return err
		}
		result, err := (plan.Planner{Renderer: renderer}).Plan(ctx, fw, []policy.Request{q})
		if err != nil {
			return err
		}
		return output(out, struct {
			Context  string `json:"context,omitempty"`
			Digest   string
			Proof    plan.Proof
			Cost     plan.Cost
			Changes  []plan.Change
			Commands []string
		}{fw.Metadata().Context, result.Digest(), result.Proof(), result.Cost(), result.Changes(), result.Commands()})
	}
	return errors.New("unsupported command")
}
func requestTraffic(source, destination, service string) (flow.Traffic, error) {
	src, err := netip.ParsePrefix(source)
	if err != nil {
		return flow.Traffic{}, err
	}
	dst, err := netip.ParsePrefix(destination)
	if err != nil {
		return flow.Traffic{}, err
	}
	parts := strings.Split(service, "/")
	if len(parts) != 2 {
		return flow.Traffic{}, errors.New("service must be protocol/port")
	}
	protocols := map[string]uint16{"tcp": 6, "udp": 17, "sctp": 132}
	protocol, ok := protocols[parts[0]]
	if !ok {
		return flow.Traffic{}, errors.New("service protocol must be tcp, udp or sctp")
	}
	port, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return flow.Traffic{}, err
	}
	a, _ := flow.PrefixRange(src)
	b, _ := flow.PrefixRange(dst)
	return flow.NewTraffic(4096, flow.TrafficRegion{Source: a, Destination: b, Protocol: flow.Interval{Low: protocol, High: protocol}, SourcePort: flow.Interval{Low: 0, High: 65535}, DestinationPort: flow.Interval{Low: uint16(port), High: uint16(port)}, ICMPType: flow.Interval{Low: 0, High: 255}, ICMPCode: flow.Interval{Low: 0, High: 255}})
}

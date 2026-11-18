package hillstone

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/parser"
)

// DefaultVirtualRouter is the StoneOS routing context of layer-3 zones that
// do not name one.
const DefaultVirtualRouter = "trust-vr"

// Options configures a Parser. The zero value parses with UTC schedules
// and the default input limits.
type Options struct {
	// Location is the device time zone for schedules and rule windows.
	Location *time.Location
	// Limits bounds the input size.
	Limits parser.Limits
	// Services is the predefined service book observed on the device. Its
	// entries replace those of DefaultServices with the same name; services
	// declared in the configuration take precedence over both.
	Services firemon.ServiceBook
	// Applications overrides entries of DefaultApplications.
	Applications firemon.ServiceBook
}

// Parser converts StoneOS running configurations to firemon.Config.
// The zero value is ready to use.
type Parser struct {
	opts Options
}

// New returns a parser with the given options.
func New(opts Options) *Parser {
	opts.Services = DefaultServices().With(opts.Services)
	opts.Applications = DefaultApplications().With(opts.Applications)
	return &Parser{opts: opts}
}

// Parse converts the text of "show configuration running".
func (p *Parser) Parse(text string) (*firemon.Config, error) {
	content, err := parser.New(text, p.opts.Limits)
	if err != nil {
		return nil, fmt.Errorf("hillstone: %w", err)
	}
	s := newState(content, p.location())
	s.book = p.book()
	for _, b := range segment(content) {
		s.dispatch(b)
	}
	cfg := s.finish()
	cfg.Applications = p.applications()
	return cfg, nil
}

// book returns the effective service book; the zero Parser uses the default.
func (p *Parser) book() firemon.ServiceBook {
	if p == nil || p.opts.Services == nil {
		return DefaultServices()
	}
	return p.opts.Services
}

func (p *Parser) location() *time.Location {
	if p == nil || p.opts.Location == nil {
		return time.UTC
	}
	return p.opts.Location
}

// state accumulates one parse.
type state struct {
	cfg       *firemon.Config
	cursor    *parser.Cursor
	loc       *time.Location
	addresses *catalog[addressDraft]
	services  *catalog[firemon.Service]
	groups    *catalog[firemon.ServiceGroup]
	schedules *catalog[firemon.Schedule]
	zones     *catalog[firemon.Zone]
	ifaces    *catalog[firemon.Interface]
	routers   *catalog[firemon.VirtualRouter]
	ruleIndex map[string]int
	ruleGroup map[string]string // aggregate rule id -> group name
	book      firemon.ServiceBook
	// place is the placement keyword of the NAT rule being read ("top",
	// "before ID", "after ID"); it appears in commands, never in a running
	// configuration, which lists rules in order.
	place string
}

func newState(content *parser.Content, loc *time.Location) *state {
	return &state{
		cfg: &firemon.Config{
			Vendor:   firemon.VendorHillstone,
			Location: loc,
			TimeZone: loc.String(),
			Semantics: firemon.Semantics{
				PolicyDestination:    firemon.AddressStageTranslated,
				IntrazoneAction:      firemon.ActionDeny,
				InterzoneAction:      firemon.ActionDeny,
				DefaultVirtualRouter: DefaultVirtualRouter,
				NumericRuleIDs:       true,
				NATOrder:             firemon.NATOrderSeparate,
				StaticNATFirst:       true,
			},
		},
		cursor:    content.Cursor(),
		loc:       loc,
		addresses: newCatalog[addressDraft](),
		services:  newCatalog[firemon.Service](),
		groups:    newCatalog[firemon.ServiceGroup](),
		schedules: newCatalog[firemon.Schedule](),
		zones:     newCatalog[firemon.Zone](),
		ifaces:    newCatalog[firemon.Interface](),
		routers:   newCatalog[firemon.VirtualRouter](),
		ruleIndex: map[string]int{},
		ruleGroup: map[string]string{},
	}
}

func (s *state) dispatch(b block) {
	words := newWords(b.head.Text)
	switch kw := words.next(); kw {
	case "Version":
		s.cfg.Version = words.rest()
	case "hostname":
		s.cfg.Hostname = words.next()
	case "address":
		s.address(b, words)
	case "service":
		s.service(b, words)
	case "servgroup":
		s.serviceGroup(b, words)
	case "schedule":
		s.schedule(b, words)
	case "zone":
		s.zone(b, words)
	case "interface":
		s.iface(b, words)
	case "ip":
		if words.next() != "vrouter" {
			break // ip name-server and similar global settings
		}
		s.vrouter(b, words)
	case "rule":
		s.rule(b, words)
	case "policy":
		s.policy(b, words)
	case "pbr-policy":
		s.pbrPolicy(b, words)
	case "policy-global":
		if containsRule(b) {
			s.policy(b, words) // rules nested in the global policy block
		} else {
			s.markRange(b.head.Number, b.last)
		}
	}
	s.markHead(b)
	if !isPolicySection(b.keyword()) {
		s.markRange(b.head.Number, b.last)
	}
}

// finish assembles the configuration and reports unrecognized lines.
func (s *state) finish() *firemon.Config {
	cfg := s.cfg
	for _, a := range s.addresses.items() {
		if a.isGroup() {
			cfg.AddressGroups = append(cfg.AddressGroups, a.group())
		} else {
			cfg.Addresses = append(cfg.Addresses, a.address())
		}
	}
	cfg.Addresses = append(cfg.Addresses, builtinAddresses(s.addresses)...)
	cfg.Services = append(s.services.items(), s.book.Services(func(name string) bool {
		return s.services.has(name) || s.groups.has(name)
	})...)
	cfg.ServiceGroups = s.groups.items()
	cfg.Schedules = s.schedules.items()
	cfg.VirtualRouters = s.routers.items()
	cfg.Zones = s.zones.items()
	cfg.Interfaces = s.interfaceVRs()
	for i := range cfg.Rules {
		cfg.Rules[i].Group = s.ruleGroup[cfg.Rules[i].Group]
	}
	for line := range s.cursor.Unparsed() {
		if !isBlank(line.Text) && line.Text != "exit" && !strings.HasPrefix(line.Text, "#") {
			cfg.Diagnostics = append(cfg.Diagnostics, firemon.Diagnostic{Line: line.Number, Text: strings.TrimSpace(line.Text), Reason: "unrecognized"})
		}
	}
	return cfg
}

// interfaceVRs assigns every interface the virtual router of its zone.
func (s *state) interfaceVRs() []firemon.Interface {
	out := s.ifaces.items()
	for i := range out {
		if z, ok := s.zones.get(out[i].Zone); ok {
			out[i].VirtualRouter = z.VirtualRouter
		}
	}
	return out
}

func (s *state) markHead(b block) { _ = s.cursor.SetParsed(b.head.Number, true) }

func (s *state) mark(l parser.Line) { _ = s.cursor.SetParsed(l.Number, true) }

func (s *state) markRange(first, last int) { _ = s.cursor.SetParsedRange(first, last, true) }

func (s *state) diagnose(l parser.Line, reason string) {
	s.mark(l)
	s.cfg.Diagnostics = append(s.cfg.Diagnostics, firemon.Diagnostic{Line: l.Number, Text: strings.TrimSpace(l.Text), Reason: reason})
}

// catalog keeps named items in first-declaration order and merges repeated
// declarations into the first one.
type catalog[T any] struct {
	index map[string]int
	list  []T
}

func newCatalog[T any]() *catalog[T] { return &catalog[T]{index: map[string]int{}} }

// upsert returns the item named name, creating it with init when missing.
func (c *catalog[T]) upsert(name string, init func() T) *T {
	if i, ok := c.index[name]; ok {
		return &c.list[i]
	}
	c.index[name] = len(c.list)
	c.list = append(c.list, init())
	return &c.list[len(c.list)-1]
}

func (c *catalog[T]) get(name string) (T, bool) {
	i, ok := c.index[name]
	if !ok {
		var zero T
		return zero, false
	}
	return c.list[i], true
}

func (c *catalog[T]) has(name string) bool {
	_, ok := c.index[name]
	return ok
}

func (c *catalog[T]) items() []T { return slices.Clone(c.list) }

// isPolicySection reports whether unrecognized lines of a block with this
// keyword are reported as diagnostics.
func isPolicySection(keyword string) bool {
	switch keyword {
	case "address", "service", "servgroup", "schedule", "zone", "interface", "ip", "rule", "policy", "policy-global", "pbr-policy":
		return true
	default:
		return false
	}
}

func containsRule(b block) bool {
	for _, l := range b.body {
		if strings.HasPrefix(strings.TrimSpace(l.Text), "rule ") {
			return true
		}
	}
	return false
}

// applications returns the effective application book; the zero Parser
// uses the default.
func (p *Parser) applications() firemon.ServiceBook {
	if p == nil || p.opts.Applications == nil {
		return DefaultApplications()
	}
	return p.opts.Applications
}

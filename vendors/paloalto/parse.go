package paloalto

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/parser"
)

// DefaultVirtualRouter is the PAN-OS virtual router present on every device.
const DefaultVirtualRouter = "default"

// Options configures a Parser. The zero value parses with UTC schedules
// and the default input limits.
type Options struct {
	// Location is the device time zone for schedules.
	Location *time.Location
	// Limits bounds the input size.
	Limits parser.Limits
	// Services is the predefined service book observed on the device. Its
	// entries replace those of DefaultServices with the same name; services
	// declared in the configuration take precedence over both.
	Services firemon.ServiceBook
}

// Parser converts PAN-OS set-format configurations to firemon.Config. The
// zero value is ready to use.
type Parser struct {
	opts Options
}

// New returns a parser with the given options.
func New(opts Options) *Parser {
	opts.Services = DefaultServices().With(opts.Services)
	return &Parser{opts: opts}
}

// Parse converts the set-format configuration text.
func (p *Parser) Parse(text string) (*firemon.Config, error) {
	content, err := parser.New(text, p.opts.Limits)
	if err != nil {
		return nil, fmt.Errorf("paloalto: %w", err)
	}
	loc := time.UTC
	if p != nil && p.opts.Location != nil {
		loc = p.opts.Location
	}
	s := newState(loc)
	s.book = DefaultServices()
	if p != nil && p.opts.Services != nil {
		s.book = p.opts.Services
	}
	stmts, _ := statements(content)
	for _, st := range stmts {
		s.dispatch(st)
	}
	return s.finish(), nil
}

// draft collects the attribute paths of one named rule in statement order.
type draft struct {
	name  string
	line  int
	attrs [][]string
}

// state accumulates one parse.
type state struct {
	cfg       *firemon.Config
	loc       *time.Location
	addresses map[string]int // name -> index in cfg.Addresses
	groups    map[string]int
	services  map[string]int
	svcGroups map[string]int
	schedules map[string]int
	zones     map[string]int
	ifaces    map[string]int
	routes    map[string]*firemon.Route // vr + "/" + name
	routeKeys []string
	routeRefs map[string]routeRef
	ifaceVR   map[string]string
	ifaceRefs map[string][]string // interface -> address object names used as its IP
	hostBits  map[string]string   // address object -> unmasked ip-netmask value
	security  *rulebook
	nat       *rulebook
	book      firemon.ServiceBook
}

func newState(loc *time.Location) *state {
	return &state{
		cfg: &firemon.Config{
			Vendor:   firemon.VendorPaloAlto,
			Location: loc,
			TimeZone: loc.String(),
			Semantics: firemon.Semantics{
				PolicyDestination:    firemon.AddressStageOriginal,
				IntrazoneAction:      firemon.ActionPermit,
				InterzoneAction:      firemon.ActionDeny,
				DefaultVirtualRouter: DefaultVirtualRouter,
			},
		},
		loc:       loc,
		addresses: map[string]int{},
		groups:    map[string]int{},
		services:  map[string]int{},
		svcGroups: map[string]int{},
		schedules: map[string]int{},
		zones:     map[string]int{},
		ifaces:    map[string]int{},
		routes:    map[string]*firemon.Route{},
		routeRefs: map[string]routeRef{},
		ifaceVR:   map[string]string{},
		ifaceRefs: map[string][]string{},
		hostBits:  map[string]string{},
		security:  newRulebook(),
		nat:       newRulebook(),
	}
}

// dispatch routes one statement by its leading path. "shared" and
// "vsys <name>" prefixes are removed: both scopes share one namespace.
func (s *state) dispatch(st statement) {
	if len(st.words) < 3 {
		return // empty containers such as "set shared service"
	}
	p := &path{words: st.words}
	head := p.next()
	switch head {
	case "shared":
		head = p.next()
	case "vsys":
		p.next()
		head = p.next()
	}
	switch head {
	case "address":
		s.address(p, st)
	case "address-group":
		s.addressGroup(p, st)
	case "service":
		s.service(p, st)
	case "service-group":
		s.serviceGroup(p, st)
	case "schedule":
		s.schedule(p, st)
	case "zone":
		s.zone(p)
	case "network":
		s.network(p, st)
	case "rulebase":
		s.rulebase(p, st)
	case "deviceconfig":
		section, key := p.next(), p.next()
		if section == "system" && key == "hostname" {
			s.cfg.Hostname = p.scalar()
		}
	case "device-group", "template":
		s.diagnose(st, "Panorama scope is not supported")
	}
}

// finish resolves deferred references and assembles the configuration.
func (s *state) finish() *firemon.Config {
	s.cfg.Services = append(s.cfg.Services, s.book.Services(func(name string) bool {
		_, isService := s.services[name]
		_, isGroup := s.svcGroups[name]
		return isService || isGroup
	})...)
	s.bindInterfaces()
	s.flushRoutes()
	s.buildSecurityRules()
	s.buildNATRules()
	return s.cfg
}

func (s *state) diagnose(st statement, reason string) {
	parts := make([]string, 0, len(st.words))
	for _, w := range st.words {
		if w.isSet {
			parts = append(parts, "[ "+strings.Join(w.list, " ")+" ]")
		} else {
			parts = append(parts, w.text)
		}
	}
	text := strings.Join(parts, " ")
	if len(text) > 160 {
		text = text[:160]
	}
	s.cfg.Diagnostics = append(s.cfg.Diagnostics, firemon.Diagnostic{Line: st.first, Text: "set " + text, Reason: reason})
}

// rulebook keeps rule drafts in first-appearance order.
type rulebook struct {
	index  map[string]int
	drafts []draft
}

func newRulebook() *rulebook { return &rulebook{index: map[string]int{}} }

func (b *rulebook) add(name string, line int, attr []string) {
	i, ok := b.index[name]
	if !ok {
		i = len(b.drafts)
		b.index[name] = i
		b.drafts = append(b.drafts, draft{name: name, line: line})
	}
	b.drafts[i].attrs = append(b.drafts[i].attrs, slices.Clone(attr))
}

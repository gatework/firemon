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
	// Applications overrides entries of DefaultApplications.
	Applications firemon.ServiceBook
}

// Parser converts PAN-OS set-format configurations to firemon.Config. The
// zero value is ready to use.
type Parser struct {
	opts Options
}

// New returns a parser with the given options.
func New(opts Options) *Parser {
	opts.Services = DefaultServices().With(opts.Services)
	opts.Applications = DefaultApplications().With(opts.Applications)
	return &Parser{opts: opts}
}

// Parse converts the set-format configuration text.
func (p *Parser) Parse(text string) (*firemon.Config, error) {
	content, err := parser.New(text, p.opts.Limits)
	if err != nil {
		return nil, fmt.Errorf("paloalto: %w", err)
	}
	loc := time.UTC
	if p.opts.Location != nil {
		loc = p.opts.Location
	}
	s := newState(loc)
	s.book = DefaultServices()
	if p.opts.Services != nil {
		s.book = p.opts.Services
	}
	stmts, strays := statements(content)
	for _, st := range stmts {
		s.dispatch(st)
	}
	for _, l := range strays {
		s.cfg.Diagnostics = append(s.cfg.Diagnostics, firemon.Diagnostic{Line: l.Number, Text: strings.TrimSpace(l.Text), Reason: "not a set statement"})
	}
	cfg := s.finish()
	cfg.Applications = p.applications()
	return cfg, nil
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
	pbf       *rulebook
	others    map[string]*rulebook // qos, dos: only their object references matter
	scope     string               // "shared" or "vsys" for the statement being read
	owners    map[string]string    // kind:name -> scope that defined it
	vsysNames map[string]bool
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
				NATOrder:             firemon.NATOrderSingle,
				PortServicesOnly:     true,
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
		pbf:       newRulebook(),
		others:    map[string]*rulebook{},
		owners:    map[string]string{},
		vsysNames: map[string]bool{},
	}
}

// claim decides whether a statement about object kind:name from the current
// scope applies. A vsys object shadows a shared object of the same name:
// the first vsys statement reports that the shared definition must be
// discarded, and later shared statements are ignored.
func (s *state) claim(kind, name string) (apply, reset bool) {
	key := kind + ":" + name
	owner, ok := s.owners[key]
	switch {
	case !ok:
		s.owners[key] = s.scope
		return true, false
	case owner == s.scope:
		return true, false
	case owner == "shared": // vsys shadows shared
		s.owners[key] = s.scope
		return true, true
	default: // shared statement for a name the vsys defines
		return false, false
	}
}

// dispatch routes one statement by its leading path. Objects under
// "shared" are visible to the vsys; a vsys object of the same name shadows
// the shared one. Configurations with several vsys are merged and reported.
func (s *state) dispatch(st statement) {
	if len(st.words) < 3 {
		return // empty containers such as "set shared service"
	}
	p := &path{words: st.words}
	head := p.next()
	s.scope = "vsys"
	switch head {
	case "shared":
		s.scope = "shared"
		head = p.next()
	case "vsys":
		name := p.next()
		if !s.vsysNames[name] {
			s.vsysNames[name] = true
			if len(s.vsysNames) == 2 {
				s.diagnose(st, "several vsys are merged into one policy")
			}
		}
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
	s.buildPBF()
	s.externalUses()
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

// applications returns the effective application book; the zero Parser
// uses the default.
func (p *Parser) applications() firemon.ServiceBook {
	if p == nil || p.opts.Applications == nil {
		return DefaultApplications()
	}
	return p.opts.Applications
}

// Capabilities describes what PAN-OS configurations express.
func Capabilities() firemon.Capabilities {
	return firemon.Capabilities{NegateAddresses: true, RuleTypes: true, ApplicationDefault: true, MaxNameLength: maxNameLength}
}

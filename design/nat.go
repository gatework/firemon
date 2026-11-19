package design

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// NATMode is the translation an intent asks for.
type NATMode uint8

// NAT modes.
const (
	NATModeUnset NATMode = iota
	// NATModeSource translates the intent's sources on the way out
	// (SNAT, PAT): to Address, or to the egress interface address.
	NATModeSource
	// NATModeDestination publishes the intent's destination, one server,
	// at Address and Port (DNAT, port forwarding).
	NATModeDestination
	// NATModeStatic maps Address one to one to the intent's destination,
	// in both directions.
	NATModeStatic
)

// String returns the mode name.
func (m NATMode) String() string {
	switch m {
	case NATModeUnset:
		return "unset"
	case NATModeSource:
		return "source"
	case NATModeDestination:
		return "destination"
	case NATModeStatic:
		return "static"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (m NATMode) MarshalText() ([]byte, error) { return []byte(m.String()), nil }

// NATIntent asks for a translation with the access. The intent's
// addresses are the real ones: the private sources of source NAT, the
// private server of destination and static NAT.
type NATIntent struct {
	Mode NATMode
	// Address is the public address: the translated source, or the
	// published destination. Zero reuses the address of an existing rule
	// on the same egress, or for source NAT the egress interface address.
	Address netip.Addr
	// Port is the published port of destination NAT; zero publishes the
	// intent's service unchanged.
	Port uint16
	// Interface is the egress of source NAT; empty takes it from routing.
	Interface string
}

// NATStatus is the outcome of the NAT part of a plan.
type NATStatus uint8

// NAT statuses.
const (
	NATStatusUnset NATStatus = iota
	// NATStatusSatisfied: the rules that match first already translate as
	// asked; nothing is added.
	NATStatusSatisfied
	// NATStatusAdded: a new rule is placed where it matches first.
	NATStatusAdded
	// NATStatusNeedsAddress: destination or static NAT without a public
	// address to use; assign one and plan again.
	NATStatusNeedsAddress
	// NATStatusIndeterminate: NAT rules that cannot be evaluated, or a
	// request the planner cannot translate safely.
	NATStatusIndeterminate
	// NATStatusConflict: an existing rule that matches first already
	// publishes the address and port elsewhere; OverrideNAT places the new
	// rule in front of it.
	NATStatusConflict
)

// String returns the status name.
func (s NATStatus) String() string {
	switch s {
	case NATStatusUnset:
		return "unset"
	case NATStatusSatisfied:
		return "satisfied"
	case NATStatusAdded:
		return "added"
	case NATStatusNeedsAddress:
		return "needs-address"
	case NATStatusIndeterminate:
		return "indeterminate"
	case NATStatusConflict:
		return "conflict"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (s NATStatus) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// NATOutcome reports the NAT part of a plan.
type NATOutcome struct {
	Status NATStatus `json:"status"`
	// Existing lists the rules that already translate the intent.
	Existing []string `json:"existing,omitempty"`
	// Rule is the new rule; Before the rule it is placed in front of, so
	// that it matches first.
	Rule   string `json:"rule,omitempty"`
	Before string `json:"before,omitempty"`
	// Address is the public address used; Interface is set instead when
	// sources take the egress interface address.
	Address   string `json:"address,omitempty"`
	Interface string `json:"interface,omitempty"`
	// Reused reports an address taken from an existing NAT rule.
	Reused bool   `json:"reused,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// errNATUnplanned carries why the NAT part could not be designed.
var errNATUnplanned = errors.New("design: NAT")

// natPlan is the NAT part being designed.
type natPlan struct {
	intent  Intent
	req     query.Request // the traffic as it arrives, before NAT
	paths   []query.Path
	public  traffic.AddressSet
	service traffic.ServiceSet // published service of destination NAT
}

// planNAT designs the NAT part of intent on p.fw. It returns the outcome,
// the changes (with the objects they need), and the intent of the access
// part: the traffic as the firewall sees it before NAT.
func (p *Planner) planNAT(intent Intent, at time.Time) (NATOutcome, []Change, Intent) {
	n := natPlan{intent: intent}
	access := intent
	access.NAT = nil
	in := intent.NAT
	n.req = intent.request(at)
	if in.Mode != NATModeSource {
		svc, err := publishedService(intent.Service, in.Port)
		if err != nil {
			return NATOutcome{Status: NATStatusIndeterminate, Reason: err.Error()}, nil, access
		}
		n.service = svc
		if !singleHost(intent.Dst) {
			return NATOutcome{Status: NATStatusIndeterminate, Reason: "destination and static NAT publish one server"}, nil, access
		}
	}
	addr, reused, ok := p.publicAddress(intent)
	if in.Mode != NATModeSource {
		if !ok {
			return NATOutcome{Status: NATStatusNeedsAddress, Reason: "no public address given or in use for " + intent.Dst.String()}, nil, access
		}
		n.public = host(addr)
		n.req.Dst, n.req.Service = n.public, n.service
		access.Dst, access.Service = n.public, n.service
	}
	res, err := p.engine(p.fw, intent).Query(n.req)
	if err != nil || len(res.Paths) == 0 {
		return NATOutcome{Status: NATStatusIndeterminate, Reason: "no path through the firewall"}, nil, access
	}
	n.paths = res.Paths
	if out, done := n.current(); done {
		return out, nil, access
	}
	if out, taken := n.taken(); taken && !intent.OverrideNAT {
		return out, nil, access
	}
	cat := newCatalog(p.fw, p.naming)
	cat.threshold = p.threshold
	out, change, err := p.natRule(n, cat, addr, reused)
	if err != nil {
		return NATOutcome{Status: NATStatusIndeterminate, Reason: err.Error()}, nil, access
	}
	changes := append(slices.Clone(cat.created), change)
	if err := p.verifyNAT(n, changes, at); err != nil {
		return NATOutcome{Status: NATStatusIndeterminate, Reason: err.Error()}, nil, access
	}
	return out, changes, access
}

// current reports whether the rules that match first already translate
// every path as asked, or cannot be evaluated.
func (n natPlan) current() (NATOutcome, bool) {
	var existing []string
	for _, path := range n.paths {
		if len(path.NATUncertain) > 0 {
			return NATOutcome{Status: NATStatusIndeterminate, Reason: "NAT rules that cannot be evaluated may match first"}, true
		}
		hit := n.hit(path)
		if hit == nil || !n.wanted(*hit) {
			return NATOutcome{}, false
		}
		id := hitID(*hit)
		if !slices.Contains(existing, id) {
			existing = append(existing, id)
		}
	}
	return NATOutcome{Status: NATStatusSatisfied, Existing: existing}, true
}

// taken reports a published address and port that the first matching
// rule already sends to another server: moving a new rule in front would
// silently take the traffic away from it.
func (n natPlan) taken() (NATOutcome, bool) {
	if n.intent.NAT.Mode == NATModeSource {
		return NATOutcome{}, false
	}
	for _, path := range n.paths {
		if h := path.DestinationNAT; h != nil && !n.wanted(*h) {
			return NATOutcome{
				Status: NATStatusConflict, Existing: []string{hitID(*h)},
				Reason: n.public.String() + " " + n.service.String() + " is already published to " + h.Translated.String(),
			}, true
		}
	}
	return NATOutcome{}, false
}

// PublishedService is the service clients reach for destination NAT: the
// intent's service on the published port, or unchanged when port is zero.
func PublishedService(s traffic.ServiceSet, port uint16) (traffic.ServiceSet, error) {
	return publishedService(s, port)
}

// hit returns the translation of the intent's side on a path.
func (n natPlan) hit(path query.Path) *query.NATHit {
	if n.intent.NAT.Mode == NATModeSource {
		if len(path.SourceNAT) != 1 {
			return nil // untranslated, or split between several rules
		}
		return &path.SourceNAT[0]
	}
	return path.DestinationNAT
}

// wanted reports whether a translation is the one asked for.
func (n natPlan) wanted(h query.NATHit) bool {
	in := n.intent.NAT
	switch in.Mode {
	case NATModeSource:
		return !in.Address.IsValid() || h.Translated.Equal(host(in.Address))
	case NATModeDestination, NATModeStatic:
		if !h.Translated.Equal(n.intent.Dst) {
			return false
		}
		if h.Rule != nil && in.Port != 0 {
			want, _ := singlePort(n.intent.Service)
			return h.Rule.Translation(firemon.NATKindDestination).Port == want
		}
		return in.Mode == NATModeDestination || h.Static != nil
	case NATModeUnset:
	}
	return false
}

func hitID(h query.NATHit) string {
	if h.Rule != nil {
		return h.Rule.Spec().ID
	}
	return "static " + h.Static.Spec().ID
}

// publicAddress chooses the public address: the intent's, or one an
// existing rule already uses for the same purpose.
func (p *Planner) publicAddress(intent Intent) (addr netip.Addr, reused, ok bool) {
	in := intent.NAT
	if in.Address.IsValid() {
		return in.Address, false, true
	}
	if in.Mode == NATModeSource {
		return netip.Addr{}, false, false // decided per egress in natRule
	}
	for _, r := range p.fw.NATRules() {
		if r.Spec().Disabled || !r.Translated(firemon.NATKindDestination).Equal(intent.Dst) {
			continue
		}
		if a, ok := hostOf(r.Match().Dst); ok {
			return a, true, true
		}
	}
	for _, m := range p.fw.StaticNATs() {
		if m.Enabled() && m.Real().Equal(intent.Dst) {
			if a, ok := hostOf(m.Mapped()); ok {
				return a, true, true
			}
		}
	}
	return netip.Addr{}, false, false
}

// natRule builds the rule (or mapping) and its placement.
func (p *Planner) natRule(n natPlan, cat *catalog, addr netip.Addr, reused bool) (NATOutcome, Change, error) {
	path := n.paths[0]
	for _, other := range n.paths[1:] {
		if other.From != path.From || other.To != path.To || other.Egress != path.Egress {
			return NATOutcome{}, nil, fmt.Errorf("%w: the intent leaves by several egresses; plan each separately", errNATUnplanned)
		}
	}
	single := p.fw.Semantics().NATOrder == firemon.NATOrderSingle
	vr := cmp.Or(n.intent.VirtualRouter, p.fw.Semantics().DefaultVirtualRouter)
	if single {
		vr = ""
	}
	var (
		r     firemon.DynamicNAT
		match traffic.Space
		out   NATOutcome
		err   error
	)
	switch n.intent.NAT.Mode {
	case NATModeSource:
		r, match, out, err = p.sourceRule(n, cat, addr, reused, single)
	case NATModeDestination:
		r, match, out = p.destinationRule(n, cat, addr, reused, single, vr)
	case NATModeStatic:
		if single {
			return p.staticPAN(n, cat, addr, reused)
		}
		m := firemon.StaticNAT{ID: p.nextStaticID(), VirtualRouter: vr, Real: inlineHost(mustHost(n.intent.Dst)), Mapped: inlineHost(addr)}
		return NATOutcome{Status: NATStatusAdded, Rule: m.ID, Address: addr.String(), Reused: reused}, AddStaticNAT{Mapping: m}, nil
	case NATModeUnset:
		err = fmt.Errorf("%w: no mode", errNATUnplanned)
	}
	if err != nil {
		return NATOutcome{}, nil, err
	}
	r.VirtualRouter = vr
	r.Name = n.intent.Name
	r.ID = p.nextNATID(r, cat, single)
	r.Name = ""
	if single {
		r.Name = r.ID
	}
	out.Status, out.Rule = NATStatusAdded, r.ID
	out.Before = p.natPlacement(r, match, single)
	return out, AddNAT{Rule: r, Before: out.Before}, nil
}

// sourceRule builds a source NAT rule matching exactly the intent, on its
// egress, to addr or to the egress interface address.
func (p *Planner) sourceRule(n natPlan, cat *catalog, addr netip.Addr, reused, single bool) (firemon.DynamicNAT, traffic.Space, NATOutcome, error) {
	path := n.paths[0]
	egress := cmp.Or(n.intent.NAT.Interface, path.Egress)
	if egress == "" {
		return firemon.DynamicNAT{}, traffic.Space{}, NATOutcome{}, fmt.Errorf("%w: the egress interface is unknown; set it", errNATUnplanned)
	}
	if !addr.IsValid() {
		addr, reused = p.egressAddress(egress)
	}
	name := "NAT_" + n.intent.Name
	r := firemon.DynamicNAT{
		Source:      refs(cat.oneAddress(cat.addressNames(n.intent.Src), n.intent.Src, name+"_src")),
		Destination: refs(cat.oneAddress(cat.addressNames(n.intent.Dst), n.intent.Dst, name+"_dst")),
		Services:    cat.oneService(cat.serviceNames(n.intent.Service), n.intent.Service, name+"_svc"),
		Egress:      egress,
	}
	out := NATOutcome{Interface: egress}
	r.TranslatedSource = firemon.Translation{Mode: firemon.TranslationModeInterface, Interface: egress, PortTranslation: true}
	if addr.IsValid() {
		r.TranslatedSource = firemon.Translation{Mode: firemon.TranslationModeAddress, Addresses: []firemon.AddressRef{inlineHost(addr)}, PortTranslation: true}
		out = NATOutcome{Address: addr.String(), Reused: reused}
	}
	if single {
		r.From, r.To, r.Egress = []string{path.From}, []string{path.To}, ""
	}
	return r, traffic.Space{Src: n.intent.Src, Dst: n.intent.Dst, Service: n.intent.Service}, out, nil
}

// destinationRule builds a destination NAT rule publishing the server at
// addr on the published service.
func (p *Planner) destinationRule(n natPlan, cat *catalog, addr netip.Addr, reused, single bool, vr string) (firemon.DynamicNAT, traffic.Space, NATOutcome) {
	r := firemon.DynamicNAT{
		Destination:           []firemon.AddressRef{inlineHost(addr)},
		Services:              cat.oneService(cat.serviceNames(n.service), n.service, "NAT_"+n.intent.Name+"_svc"),
		TranslatedDestination: firemon.Translation{Mode: firemon.TranslationModeAddress, Addresses: []firemon.AddressRef{inlineHost(mustHost(n.intent.Dst))}},
	}
	if n.intent.NAT.Port != 0 {
		r.TranslatedDestination.Port, _ = singlePort(n.intent.Service)
	}
	if single {
		// PAN-OS matches the original packet: the zone the public address
		// routes to, before translation.
		r.From, r.To = []string{n.paths[0].From}, []string{p.zoneOf(n.public, vr)}
	}
	match := traffic.Space{Src: traffic.AnyAddress(), Dst: n.public, Service: n.service}
	return r, match, NATOutcome{Address: addr.String(), Reused: reused}
}

// staticPAN builds a PAN-OS bi-directional static-ip rule: the server's
// outbound translation, whose reverse half publishes it.
func (p *Planner) staticPAN(n natPlan, cat *catalog, addr netip.Addr, reused bool) (NATOutcome, Change, error) {
	server := mustHost(n.intent.Dst)
	outside := n.paths[0].From
	r := firemon.DynamicNAT{
		From: []string{p.zoneOf(n.intent.Dst, "")}, To: []string{outside},
		Source:           []firemon.AddressRef{inlineHost(server)},
		TranslatedSource: firemon.Translation{Mode: firemon.TranslationModeAddress, Addresses: []firemon.AddressRef{inlineHost(addr)}},
	}
	r.Name = n.intent.Name
	r.ID = p.nextNATID(r, cat, true)
	r.Name = r.ID
	match := traffic.Space{Src: n.intent.Dst, Dst: traffic.AnyAddress(), Service: traffic.AnyService()}
	before := p.natPlacement(r, match, true)
	out := NATOutcome{Status: NATStatusAdded, Rule: r.ID, Before: before, Address: addr.String(), Reused: reused}
	return out, AddNAT{Rule: r, Before: before, Bidirectional: true}, nil
}

// natPlacement returns the first rule of the new rule's NAT list that may
// match some of its traffic: the new rule goes in front of it so that it
// matches first. Empty means the end of the list.
func (p *Planner) natPlacement(r firemon.DynamicNAT, match traffic.Space, single bool) string {
	side := NATSide(r)
	for _, e := range p.fw.NATRules() {
		spec := e.Spec()
		if spec.Disabled || (!single && NATSide(spec) != side) {
			continue // disabled rules match nothing
		}
		if spec.Egress != "" && r.Egress != "" && spec.Egress != r.Egress {
			continue
		}
		if single && !zonesMeet(spec.From, r.From) {
			continue
		}
		if e.Bound().Overlaps(match) {
			return spec.ID
		}
	}
	return ""
}

func zonesMeet(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	return slices.ContainsFunc(a, func(z string) bool { return slices.Contains(b, z) })
}

// nextNATID returns a free identifier: the next number of the rule's NAT
// list on vendors with numeric IDs, a unique name otherwise.
func (p *Planner) nextNATID(r firemon.DynamicNAT, cat *catalog, single bool) string {
	if !p.fw.Semantics().NumericRuleIDs || single {
		var base string
		switch {
		case r.TranslatedDestination.Mode == firemon.TranslationModeAddress && len(r.TranslatedDestination.Addresses) == 1:
			base = "DNAT_" + r.TranslatedDestination.Addresses[0].Entry.Prefix.Addr().String()
			if r.TranslatedDestination.Port != 0 {
				base += "-" + strconv.Itoa(int(r.TranslatedDestination.Port))
			}
		case len(r.To) == 1:
			base = "To_" + r.To[0]
		default:
			base = "SNAT"
		}
		if r.Name != "" {
			base += "_" + r.Name
		}
		return cat.unique(base)
	}
	highest := 0
	for _, e := range p.fw.NATRules() {
		if NATSide(e.Spec()) != NATSide(r) {
			continue
		}
		if v, err := strconv.Atoi(e.Spec().ID); err == nil {
			highest = max(highest, v)
		}
	}
	return strconv.Itoa(highest + 1)
}

func (p *Planner) nextStaticID() string {
	highest := 0
	for _, m := range p.fw.StaticNATs() {
		if v, err := strconv.Atoi(m.Spec().ID); err == nil {
			highest = max(highest, v)
		}
	}
	return strconv.Itoa(highest + 1)
}

// egressAddress reuses the address an enabled source NAT rule on the same
// egress translates to, as operators keep one public address per uplink.
func (p *Planner) egressAddress(egress string) (netip.Addr, bool) {
	for _, r := range p.fw.NATRulesFor(firemon.NATKindSource) {
		spec := r.Spec()
		if spec.Disabled || spec.Egress != egress || spec.TranslatedSource.Mode != firemon.TranslationModeAddress {
			continue
		}
		if a, ok := hostOf(r.Translated(firemon.NATKindSource)); ok {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// zoneOf returns the zone routing sends addresses to; empty when unknown.
func (p *Planner) zoneOf(s traffic.AddressSet, vr string) string {
	t, ok := p.fw.RoutingTable(cmp.Or(vr, p.fw.Semantics().DefaultVirtualRouter))
	if !ok {
		return ""
	}
	egress, _ := t.Lookup(s)
	for _, e := range egress {
		if e.Zone != "" {
			return e.Zone
		}
	}
	return ""
}

// verifyNAT applies the NAT changes and checks that every path of the
// intent is now translated as asked by the new rule.
func (p *Planner) verifyNAT(n natPlan, changes []Change, at time.Time) error {
	cfg := p.fw.Config()
	if err := Apply(cfg, changes); err != nil {
		return err
	}
	after, err := firemon.Compile(cfg)
	if err != nil {
		return err
	}
	res, err := p.engine(after, n.intent).Query(n.req)
	if err != nil {
		return err
	}
	if len(res.Paths) == 0 {
		return fmt.Errorf("%w: no path after the change", errNATUnplanned)
	}
	for _, path := range res.Paths {
		hit := n.hit(path)
		if hit == nil || !n.wanted(*hit) {
			return fmt.Errorf("%w: %s -> %s is not translated as asked after the change", errNATUnplanned, path.From, path.To)
		}
	}
	return nil
}

// publishedService is the service clients reach: the intent's service on
// the published port.
func publishedService(s traffic.ServiceSet, port uint16) (traffic.ServiceSet, error) {
	if port == 0 {
		return s, nil
	}
	if _, ok := singlePort(s); !ok {
		return traffic.ServiceSet{}, fmt.Errorf("%w: port translation needs one TCP or UDP port, not %s", errNATUnplanned, s)
	}
	for r := range s.All() {
		return traffic.NewService(r.ProtocolLow, r.Src, traffic.Port(port)), nil
	}
	return traffic.ServiceSet{}, nil
}

// singlePort returns the one destination port of a single-protocol
// service.
func singlePort(s traffic.ServiceSet) (uint16, bool) {
	var port uint16
	n := 0
	for r := range s.All() {
		n++
		if r.ProtocolLow != r.ProtocolHigh || !r.ProtocolLow.HasPorts() || r.Dst.Low != r.Dst.High {
			return 0, false
		}
		port = r.Dst.Low
	}
	return port, n == 1
}

func host(a netip.Addr) traffic.AddressSet {
	return traffic.NewAddressSet(netip.PrefixFrom(a, a.BitLen()))
}

func hostOf(s traffic.AddressSet) (netip.Addr, bool) {
	rs := s.Ranges()
	if len(rs) != 1 || rs[0].From() != rs[0].To() {
		return netip.Addr{}, false
	}
	return rs[0].From(), true
}

func singleHost(s traffic.AddressSet) bool {
	_, ok := hostOf(s)
	return ok
}

func mustHost(s traffic.AddressSet) netip.Addr {
	a, _ := hostOf(s)
	return a
}

func inlineHost(a netip.Addr) firemon.AddressRef { return firemon.InlineAddress(firemon.HostEntry(a)) }

func refs(names []string) []firemon.AddressRef {
	out := make([]firemon.AddressRef, len(names))
	for i, n := range names {
		out[i] = firemon.NamedAddress(n)
	}
	return out
}

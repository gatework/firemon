package hillstone

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/gatework/firemon"
)

// zone parses: zone "NAME" [l2|tap]
//
//	vrouter "VR" | description "TEXT" | other zone settings (ignored)
func (s *state) zone(b block, head *words) {
	name := head.next()
	mode := firemon.ZoneModeLayer3
	switch head.next() {
	case "l2":
		mode = firemon.ZoneModeLayer2
	case "tap":
		mode = firemon.ZoneModeTap
	}
	z := s.zones.upsert(name, func() firemon.Zone {
		vr := DefaultVirtualRouter
		if mode != firemon.ZoneModeLayer3 {
			vr = ""
		}
		return firemon.Zone{Name: name, Mode: mode, VirtualRouter: vr}
	})
	for _, l := range b.body {
		w := newWords(l.Text)
		switch w.next() {
		case "vrouter":
			z.VirtualRouter = w.next()
		case "description":
			z.Description = w.next()
		case "bind":
			s.bindPolicy(w, name, "")
		}
		s.mark(l) // anti-attack and identification settings do not affect matching
	}
}

// iface parses: interface NAME [local]
//
//	zone "ZONE" | ip address A MASK [secondary] | ipv6 address A/LEN
//	description "TEXT" | management and tunnel settings (ignored)
func (s *state) iface(b block, head *words) {
	name := head.next()
	i := s.ifaces.upsert(name, func() firemon.Interface { return firemon.Interface{Name: name} })
	for _, l := range b.body {
		w := newWords(l.Text)
		switch kw := w.next(); kw {
		case "zone":
			i.Zone = w.next()
		case "description":
			i.Description = w.next()
		case "bind":
			s.bindPolicy(w, "", name)
		case "ip", "ipv6":
			if w.peek() != "address" {
				break
			}
			w.next()
			p, ok := interfacePrefix(w.next(), w.peek())
			if !ok {
				s.diagnose(l, "invalid interface address")
				continue
			}
			i.Addresses = append(i.Addresses, p)
		}
		s.mark(l)
	}
}

// vrouter parses: ip vrouter "VR" with its static routes and NAT rules.
func (s *state) vrouter(b block, head *words) {
	vr := head.next()
	s.routers.upsert(vr, func() firemon.VirtualRouter { return firemon.VirtualRouter{Name: vr} })
	for _, l := range b.body {
		w := newWords(l.Text)
		var ok bool
		switch kw := w.next(); kw {
		case "ip", "ipv6":
			if w.next() != "route" {
				continue
			}
			ok = s.route(vr, w)
		case "snatrule", "dnatrule":
			ok = s.dynamicNAT(vr, kw, w)
		case "bnatrule":
			ok = s.staticNAT(vr, w)
		default:
			continue
		}
		if !ok {
			s.diagnose(l, "unsupported "+strings.Fields(l.Text)[0]+" syntax")
			continue
		}
		s.mark(l)
	}
}

// route parses: ip route PREFIX|ADDR MASK [NEXTHOP] ["INTERFACE"|INTERFACE]
// [vrouter "VR"] [distance N] [weight N] [description "TEXT"].
func (s *state) route(vr string, w *words) bool {
	dstText := w.next()
	mask := ""
	if !strings.Contains(dstText, "/") {
		if _, ok := maskBits(w.peek()); ok {
			mask = w.next()
		}
	}
	dst, ok := parsePrefix(dstText, mask)
	if !ok {
		return false
	}
	r := firemon.Route{VirtualRouter: vr, Destination: dst, Distance: 1}
	for !w.done() {
		if !routeClause(&r, w) {
			return false
		}
	}
	s.cfg.Routes = append(s.cfg.Routes, r)
	return true
}

func routeClause(r *firemon.Route, w *words) bool {
	t := w.toks[w.pos]
	w.next()
	switch {
	case t.quoted:
		r.Interface = t.text
	case t.text == "description":
		r.Description = w.next()
	case t.text == "vrouter":
		r.NextVirtualRouter = w.next()
	case t.text == "distance" || t.text == "weight":
		n, err := strconv.ParseUint(w.next(), 10, 32)
		if err != nil {
			return false
		}
		if t.text == "distance" {
			r.Distance = uint32(n)
		} else {
			r.Metric = uint32(n)
		}
	default:
		if hop, err := netip.ParseAddr(t.text); err == nil {
			r.NextHop = hop
			return true
		}
		if !looksLikeInterface(t.text) {
			return false
		}
		r.Interface = t.text
	}
	return true
}

// looksLikeInterface accepts StoneOS interface names such as ethernet0/1,
// xethernet0/24.401, tunnel3, aggregate1 and null0.
func looksLikeInterface(name string) bool {
	if name == "" || strings.ContainsAny(name, " \"") {
		return false
	}
	last := name[len(name)-1]
	return last >= '0' && last <= '9'
}

// dynamicNAT parses:
//
//	snatrule id N [from OPERAND] [to OPERAND] [service "S"] [eif IF]
//	  trans-to (ip A | address-book "X" | eif-ip) mode static|dynamicip|dynamicport
//	  [sticky] [log] [disable]
//	dnatrule id N [from OPERAND] [to OPERAND] [service "S"]
//	  trans-to (ip A | address-book "X") [port N] [load-balance] [log] [disable]
//
// OPERAND is address-book "X", ip PREFIX or range A B.
func (s *state) dynamicNAT(vr, kw string, w *words) bool {
	n := firemon.DynamicNAT{VirtualRouter: vr}
	var t firemon.Translation
	for !w.done() {
		if !s.natClause(&n, &t, w) {
			return false
		}
	}
	if n.ID == "" || t.Mode == firemon.TranslationModeUnset {
		return false
	}
	if kw == "dnatrule" {
		n.TranslatedDestination = t
	} else {
		n.TranslatedSource = t
	}
	s.insertNAT(n, kw == "dnatrule")
	return true
}

// insertNAT adds a rule at its placement among the rules of its list.
func (s *state) insertNAT(n firemon.DynamicNAT, destination bool) {
	place := s.place
	s.place = ""
	sameList := func(o firemon.DynamicNAT) bool {
		return (o.TranslatedDestination.Mode == firemon.TranslationModeAddress) == destination
	}
	at := len(s.cfg.DynamicNATs)
	kw, ref, _ := strings.Cut(place, " ")
	switch kw {
	case "top":
		if i := slices.IndexFunc(s.cfg.DynamicNATs, sameList); i >= 0 {
			at = i
		}
	case "before", "after":
		if i := slices.IndexFunc(s.cfg.DynamicNATs, func(o firemon.DynamicNAT) bool { return o.ID == ref && sameList(o) }); i >= 0 {
			at = i
			if kw == "after" {
				at++
			}
		}
	}
	s.cfg.DynamicNATs = slices.Insert(s.cfg.DynamicNATs, at, n)
}

func (s *state) natClause(n *firemon.DynamicNAT, t *firemon.Translation, w *words) bool {
	switch kw := w.next(); kw {
	case "id":
		n.ID = w.next()
	case "from", "to":
		ref, ok := natOperand(w)
		switch {
		case !ok:
			return false
		case ref.Name == anyName:
			// The predefined Any object: an empty list matches any.
		case kw == "from":
			n.Source = append(n.Source, ref)
		default:
			n.Destination = append(n.Destination, ref)
		}
	case "service":
		if svc := w.next(); svc != anyName {
			n.Services = append(n.Services, svc)
		}
	case "eif":
		n.Egress = w.next()
	case "trans-to":
		return translation(n, t, w)
	case "port":
		p, ok := portNumber(w.next())
		t.Port = p
		return ok
	case "mode":
		t.PortTranslation = w.next() == "dynamicport"
	case "disable":
		n.Disabled = true
	case "description":
		n.Description = w.next()
	case "sticky", "log", "load-balance":
	case "top":
		s.place = kw
	case "before", "after":
		s.place = kw + " " + w.next()
	case "track-ping", "track-tcp":
		w.next() // the tracked object
	case "ingress-interface", "evr":
		// Narrow the match in ways the model does not evaluate.
		n.Unsupported = append(n.Unsupported, kw+" "+w.next())
	default:
		n.Unsupported = append(n.Unsupported, "unrecognized "+kw+" "+w.rest())
		for !w.done() {
			w.next()
		}
	}
	return true
}

func translation(n *firemon.DynamicNAT, t *firemon.Translation, w *words) bool {
	port, pat := t.Port, t.PortTranslation
	if w.peek() == "eif-ip" {
		w.next()
		*t = firemon.Translation{Mode: firemon.TranslationModeInterface, Interface: n.Egress, Port: port, PortTranslation: pat}
		return true
	}
	ref, ok := natOperand(w)
	if !ok {
		return false
	}
	*t = firemon.Translation{Mode: firemon.TranslationModeAddress, Addresses: []firemon.AddressRef{ref}, Port: port, PortTranslation: pat}
	return true
}

// staticNAT parses: bnatrule id N virtual OPERAND real OPERAND [disable].
func (s *state) staticNAT(vr string, w *words) bool {
	m := firemon.StaticNAT{VirtualRouter: vr}
	for !w.done() {
		switch w.next() {
		case "id":
			m.ID = w.next()
		case "virtual":
			ref, ok := natOperand(w)
			if !ok {
				return false
			}
			m.Mapped = ref
		case "real":
			ref, ok := natOperand(w)
			if !ok {
				return false
			}
			m.Real = ref
		case "disable":
			m.Disabled = true
		case "log":
		default:
			return false
		}
	}
	if m.ID == "" || (m.Real == firemon.AddressRef{}) || (m.Mapped == firemon.AddressRef{}) {
		return false
	}
	s.cfg.StaticNATs = append(s.cfg.StaticNATs, m)
	return true
}

// natOperand parses address-book "X", ip PREFIX or range A B.
func natOperand(w *words) (firemon.AddressRef, bool) {
	switch kind := w.next(); kind {
	case "address-book", "addr-book":
		return firemon.NamedAddress(w.next()), true
	case "ip", "range":
		e, ok := addressEntry(kind, w)
		return firemon.InlineAddress(e), ok
	default:
		return firemon.AddressRef{}, false
	}
}

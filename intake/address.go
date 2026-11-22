package intake

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/gatework/firemon/traffic"
)

// addressSide accumulates one address field.
type addressSide struct {
	field   Field
	set     traffic.AddressSet
	items   []traffic.AddressSet // each accepted item, in input order
	domains []string
	notes   []Note
}

// parseAddresses reads one address field. Domains are accepted on the
// destination side only.
func parseAddresses(text string, field Field) addressSide {
	side := addressSide{field: field}
	tokens := fields(text)
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		// "10.0.0.0 255.255.255.0": an address followed by a dotted mask.
		if i+1 < len(tokens) && isIPv4(tok) && isMask(tokens[i+1]) {
			n, _ := maskLength(tokens[i+1])
			side.add(tok+" "+tokens[i+1], tok+"/"+strconv.Itoa(n), CodeMask)
			i++
			continue
		}
		side.item(tok)
	}
	return side
}

func (s *addressSide) item(tok string) {
	low := strings.ToLower(tok)
	switch {
	case low == "any" || low == "all" || tok == "*":
		s.merge(tok, traffic.AnyAddress(), CodeUnset)
	case strings.Contains(tok, "*") && !strings.ContainsAny(tok, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"):
		s.wildcard(tok)
	case strings.ContainsAny(tok, "-~") && !looksLikeDomain(tok):
		s.rangeItem(tok)
	case strings.Contains(tok, "/"):
		s.prefixItem(tok)
	case isAddr(tok):
		a, _ := netip.ParseAddr(tok)
		a = a.Unmap()
		s.merge(tok, traffic.NewAddressSet(netip.PrefixFrom(a, a.BitLen())), CodeUnset)
		if a.Is4() && (a.As4()[3] == 0 || a.As4()[3] == 255) {
			// Taken as the host it names; the note asks whether a mask is missing.
			s.notes = append(s.notes, Note{Field: s.field, Code: CodeNetworkHost, Input: tok, Result: a.String() + "/32"})
		}
	case looksLikeDomain(tok):
		if s.field != FieldDestination {
			s.notes = append(s.notes, Note{Field: s.field, Code: CodeUnsupported, Input: tok})
			return
		}
		name := strings.TrimSuffix(strings.ToLower(tok), ".")
		s.domains = append(s.domains, name)
		s.notes = append(s.notes, Note{Field: s.field, Code: CodeDomain, Input: tok, Result: name})
	default:
		s.notes = append(s.notes, Note{Field: s.field, Code: CodeInvalid, Input: tok})
	}
}

// add parses a canonical traffic expression and merges it.
func (s *addressSide) add(input, expr string, code Code) {
	set, err := traffic.ParseAddressSet(expr)
	if err != nil {
		s.notes = append(s.notes, Note{Field: s.field, Code: CodeInvalid, Input: input})
		return
	}
	s.merge(input, set, code)
}

// merge adds set; items already covered are reported as duplicates.
func (s *addressSide) merge(input string, set traffic.AddressSet, code Code) {
	if !s.set.IsEmpty() && s.set.ContainsSet(set) {
		s.notes = append(s.notes, Note{Field: s.field, Code: CodeDuplicate, Input: input, Result: set.String()})
		return
	}
	s.set = s.set.Union(set)
	s.items = append(s.items, set)
	if code != CodeUnset {
		s.notes = append(s.notes, Note{Field: s.field, Code: code, Input: input, Result: set.String()})
	}
}

func (s *addressSide) prefixItem(tok string) {
	addr, bits, _ := strings.Cut(tok, "/")
	if isMask(bits) { // "10.0.0.0/255.255.255.0"
		n, _ := maskLength(bits)
		bits = strconv.Itoa(n)
	}
	p, err := netip.ParsePrefix(addr + "/" + bits)
	if err != nil {
		s.notes = append(s.notes, Note{Field: s.field, Code: CodeInvalid, Input: tok})
		return
	}
	code := CodeUnset
	if p != p.Masked() {
		code = CodeMasked
	}
	s.merge(tok, traffic.NewAddressSet(p), code)
}

// rangeItem reads "a-b", "a~b" and the shortened "10.1.1.1-9" or
// "10.1.1.1-2.9" forms, which repeat the leading octets of a.
func (s *addressSide) rangeItem(tok string) {
	from, to, _ := strings.Cut(strings.ReplaceAll(tok, "~", "-"), "-")
	from, to = strings.TrimSpace(from), strings.TrimSpace(to)
	code := CodeUnset
	if isIPv4(from) && !isIPv4(to) {
		octets := strings.Split(from, ".")
		tail := strings.Split(to, ".")
		if len(tail) < 4 {
			to = strings.Join(append(octets[:4-len(tail)], tail...), ".")
			code = CodeShortRange
		}
	}
	s.add(tok, from+"-"+to, code)
}

// wildcard reads "10.1.1.*" and "10.1.*.*" (trailing octets only).
func (s *addressSide) wildcard(tok string) {
	octets := strings.Split(tok, ".")
	if len(octets) != 4 {
		s.notes = append(s.notes, Note{Field: s.field, Code: CodeInvalid, Input: tok})
		return
	}
	fixed := 0
	for fixed < 4 && octets[fixed] != "*" {
		fixed++
	}
	for _, o := range octets[fixed:] {
		if o != "*" {
			s.notes = append(s.notes, Note{Field: s.field, Code: CodeInvalid, Input: tok})
			return
		}
	}
	for i := fixed; i < 4; i++ {
		octets[i] = "0"
	}
	s.add(tok, strings.Join(octets, ".")+"/"+strconv.Itoa(fixed*8), CodeWildcard)
}

func isAddr(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

func isIPv4(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4()
}

func isMask(s string) bool {
	_, ok := maskLength(s)
	return ok
}

// maskLength converts a contiguous dotted IPv4 mask to a prefix length.
func maskLength(s string) (int, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return 0, false
	}
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n := 0
	for v&0x80000000 != 0 {
		n++
		v <<= 1
	}
	return n, v == 0
}

// looksLikeDomain accepts host names and wildcard domains with at least one
// dot and one letter.
func looksLikeDomain(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if !strings.Contains(s, ".") || isAddr(s) {
		return false
	}
	letter := false
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			letter = true
		case r >= '0' && r <= '9', r == '-', r == '.':
		case r == '*' && i == 0:
		default:
			return false
		}
	}
	return letter
}

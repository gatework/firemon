package operations

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/policy"
)

// InputError locates an invalid field in the original application. A rejected
// item is never reduced to the subset of tokens that happened to parse.
type InputError struct {
	Field  string `json:"field"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

func (e *InputError) Error() string {
	return fmt.Sprintf("%s %q: %s", e.Field, e.Value, e.Reason)
}
func (e *InputError) Unwrap() error { return ErrInvalid }

// NormalizedInput retains the independent sets of one business request. Their
// same-family product is exact; different requests are never cross-multiplied.
type NormalizedInput struct {
	Sources          []flow.AddressRange `json:"sources"`
	Destinations     []flow.AddressRange `json:"destinations"`
	Services         []fm.ServiceTerm    `json:"services"`
	AllServices      bool                `json:"all_services"`
	ServiceSpecified bool                `json:"service_specified"`
}

type inputToken struct{ raw, text string }

var inputOperator = regexp.MustCompile(`\s*([/-])\s*`)

func inputRune(r rune) rune {
	switch {
	case r >= '\uff01' && r <= '\uff5e':
		return r - 0xfee0
	case r == '\u3001':
		return ','
	case unicode.IsSpace(r):
		return ' '
	default:
		return r
	}
}

func inputSpace(r rune) bool { return unicode.IsSpace(r) || r == '\ufeff' }

// inputText removes clipboard wrapping, including a quoted entire cell. Quotes
// around individual values remain for the tokenizer to pair independently.
func inputText(raw string) string {
	raw = strings.TrimFunc(raw, inputSpace)
	first, n := utf8.DecodeRuneInString(raw)
	last, m := utf8.DecodeLastRuneInString(raw)
	first = inputRune(first)
	if len(raw) >= n+m && (first == '\'' || first == '"') && first == inputRune(last) {
		inner := raw[n : len(raw)-m]
		if !strings.ContainsFunc(inner, func(r rune) bool { return inputRune(r) == first }) {
			return strings.TrimFunc(inner, inputSpace)
		}
	}
	return raw
}

// inputTokens preserves original values for diagnostics. Whitespace is a list
// separator except around prefix/range operators or inside a quoted value.
func inputTokens(ctx context.Context, raw string, limit int) ([]inputToken, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw = inputText(raw)
	tokens := make([]inputToken, 0)
	start, end := -1, 0
	var quote, previous rune
	flush := func() error {
		if start < 0 {
			return nil
		}
		if len(tokens) >= limit {
			return policy.ErrBudget
		}
		value := raw[start:end]
		text := strings.Map(inputRune, value)
		text = strings.TrimSpace(unquoteInput(text))
		text = inputOperator.ReplaceAllString(text, "$1")
		tokens = append(tokens, inputToken{raw: value, text: text})
		start, previous = -1, 0
		return ctx.Err()
	}
	for i := 0; i < len(raw); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r, size := utf8.DecodeRuneInString(raw[i:])
		r = inputRune(r)
		if quote == 0 && inputSpace(r) {
			// Consume the run once; repeatedly looking ahead from every space
			// would make a large pasted cell quadratic.
			for i += size; i < len(raw); i += size {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				r, size = utf8.DecodeRuneInString(raw[i:])
				r = inputRune(r)
				if !inputSpace(r) {
					break
				}
			}
			operator := previous == '/' || previous == '-' || r == '/' || r == '-'
			if !operator || i == len(raw) {
				if err := flush(); err != nil {
					return nil, err
				}
			}
			continue
		}
		if quote == 0 && (r == ',' || r == ';') {
			if err := flush(); err != nil {
				return nil, err
			}
			i += size
			continue
		}
		if start < 0 {
			start = i
			if r == '\'' || r == '"' {
				quote = r
			}
		} else if r == quote {
			quote = 0
		}
		end, previous = i+size, r
		i += size
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return tokens, ctx.Err()
}

func parseAddresses(ctx context.Context, raw, field string, limit int) (flow.AddressSet, error) {
	tokens, err := inputTokens(ctx, raw, limit)
	if err != nil {
		return flow.AddressSet{}, err
	}
	if len(tokens) == 0 {
		return flow.AddressSet{}, &InputError{Field: field, Value: raw, Reason: "address is required"}
	}
	ranges := make([]flow.AddressRange, 0, len(tokens))
	for _, token := range tokens {
		if err := ctx.Err(); err != nil {
			return flow.AddressSet{}, err
		}
		var r flow.AddressRange
		switch {
		case strings.Contains(token.text, "/"):
			var prefix netip.Prefix
			prefix, err = netip.ParsePrefix(token.text)
			if err == nil {
				r, err = flow.PrefixRange(prefix)
			}
		case strings.Contains(token.text, "-"):
			first, last, _ := strings.Cut(token.text, "-")
			r.First, err = netip.ParseAddr(first)
			if err == nil {
				r.Last, err = netip.ParseAddr(last)
			}
		default:
			r.First, err = netip.ParseAddr(token.text)
			r.Last = r.First
		}
		if err != nil || !r.Valid() {
			return flow.AddressSet{}, &InputError{
				Field: field, Value: token.raw, Reason: "invalid ip, prefix or address range",
			}
		}
		ranges = append(ranges, r)
	}
	return flow.NewAddressSet(ranges...)
}

func unquoteInput(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

type serviceInput struct {
	terms          []fm.ServiceTerm
	all, specified bool
}

func parseServices(ctx context.Context, raw string, limit int) (serviceInput, error) {
	tokens, err := inputTokens(ctx, raw, limit)
	if err != nil {
		return serviceInput{}, err
	}
	base := fm.ServiceTerm{
		Protocol: flow.Interval{High: 255}, SourcePort: flow.Interval{High: 65535},
		DestinationPort: flow.Interval{High: 65535}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255},
	}
	all := len(tokens) == 0 && inputText(raw) == "" || len(tokens) == 1 && strings.EqualFold(tokens[0].text, "any")
	if all {
		if limit < 1 {
			return serviceInput{}, policy.ErrBudget
		}
		return serviceInput{terms: []fm.ServiceTerm{base}, all: true, specified: len(tokens) != 0}, nil
	}
	terms := make([]fm.ServiceTerm, 0, len(tokens))
	for _, token := range tokens {
		if err := ctx.Err(); err != nil {
			return serviceInput{}, err
		}
		protocol, ports, explicit := strings.Cut(strings.ToLower(token.text), "/")
		if !explicit {
			protocol, ports = "tcp", protocol
		}
		term := base
		switch protocol {
		case "tcp":
			term.Protocol = flow.Interval{Low: 6, High: 6}
		case "udp":
			term.Protocol = flow.Interval{Low: 17, High: 17}
		default:
			return serviceInput{}, &InputError{Field: "service", Value: token.raw, Reason: "use tcp/port or udp/port"}
		}
		low, high, span := strings.Cut(ports, "-")
		if !span {
			high = low
		}
		a, errA := strconv.ParseUint(low, 10, 16)
		b, errB := strconv.ParseUint(high, 10, 16)
		if errA != nil || errB != nil || a > b {
			return serviceInput{}, &InputError{Field: "service", Value: token.raw, Reason: "invalid port or port range"}
		}
		term.DestinationPort = flow.Interval{Low: uint16(a), High: uint16(b)}
		terms = append(terms, term)
	}
	if len(terms) == 0 {
		return serviceInput{}, &InputError{Field: "service", Value: raw, Reason: "service is empty after normalization"}
	}
	slices.SortFunc(terms, func(a, b fm.ServiceTerm) int {
		return cmp.Or(cmp.Compare(a.Protocol.Low, b.Protocol.Low),
			cmp.Compare(a.DestinationPort.Low, b.DestinationPort.Low),
			cmp.Compare(a.DestinationPort.High, b.DestinationPort.High))
	})
	// Coalesce only ports within the same protocol; this cannot add traffic.
	out := terms[:0]
	for _, term := range terms {
		if len(out) > 0 {
			last := &out[len(out)-1]
			if last.Protocol == term.Protocol && uint32(term.DestinationPort.Low) <= uint32(last.DestinationPort.High)+1 {
				last.DestinationPort.High = max(last.DestinationPort.High, term.DestinationPort.High)
				continue
			}
		}
		out = append(out, term)
	}
	return serviceInput{terms: out, specified: true}, ctx.Err()
}

func normalizeInput(ctx context.Context, a AccessRequest, limit int) (AccessRequest, *NormalizedInput, error) {
	if err := ctx.Err(); err != nil {
		return a, nil, err
	}
	if a.Src == "" && a.Dst == "" && a.Service == "" {
		if a.Traffic.Empty() {
			return a, nil, &InputError{Field: "traffic", Reason: "provide src and dst or explicit traffic"}
		}
		return a, nil, nil
	}
	if !a.Traffic.Empty() || a.Native != nil || len(a.WireCandidates) != 0 {
		return a, nil, &InputError{Field: "traffic", Reason: "text and native traffic inputs cannot be combined"}
	}
	if a.View != "" && a.View != inventory.Original {
		return a, nil, &InputError{Field: "view", Value: string(a.View), Reason: "text input uses automatic address association"}
	}
	for _, target := range a.Targets {
		if target.Device == "" || !target.Request.Traffic.Empty() {
			return a, nil, &InputError{Field: "targets", Value: target.Device, Reason: "target needs a device and must not contain traffic"}
		}
	}
	src, err := parseAddresses(ctx, a.Src, "src", limit)
	if err != nil {
		return a, nil, err
	}
	dst, err := parseAddresses(ctx, a.Dst, "dst", limit)
	if err != nil {
		return a, nil, err
	}
	services, err := parseServices(ctx, a.Service, limit)
	if err != nil {
		return a, nil, err
	}
	normalized := &NormalizedInput{
		Sources: src.Ranges(), Destinations: dst.Ranges(), Services: services.terms,
		AllServices: services.all, ServiceSpecified: services.specified,
	}
	src4, src6 := inputFamilies(normalized.Sources)
	dst4, dst6 := inputFamilies(normalized.Destinations)
	if src4 != dst4 || src6 != dst6 {
		return a, nil, &InputError{
			Field: "dst", Value: a.Dst, Reason: "source and destination must include the same address families",
		}
	}
	var regions []flow.TrafficRegion
	for _, s := range normalized.Sources {
		for _, d := range normalized.Destinations {
			if s.First.BitLen() != d.First.BitLen() {
				continue
			}
			for _, term := range services.terms {
				if err := ctx.Err(); err != nil {
					return a, nil, err
				}
				if len(regions) >= limit {
					return a, nil, policy.ErrBudget
				}
				regions = append(regions, flow.TrafficRegion{
					Source: s, Destination: d, Protocol: term.Protocol, SourcePort: term.SourcePort,
					DestinationPort: term.DestinationPort, ICMPType: term.ICMPType, ICMPCode: term.ICMPCode,
				})
			}
		}
	}
	traffic, err := flow.NewTraffic(limit, regions...)
	if err != nil {
		return a, nil, err
	}
	if err := ctx.Err(); err != nil {
		return a, nil, err
	}
	a.Traffic = traffic
	return a, normalized, nil
}

func inputFamilies(ranges []flow.AddressRange) (has4, has6 bool) {
	for _, r := range ranges {
		has4 = has4 || r.First.Is4()
		has6 = has6 || r.First.Is6()
	}
	return has4, has6
}

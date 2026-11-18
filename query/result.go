package query

import (
	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// Verdict summarizes how the firewall treats a request.
type Verdict uint8

// Verdicts.
const (
	VerdictUnset Verdict = iota
	// VerdictAllowed means every packet of the request is permitted.
	VerdictAllowed
	// VerdictDenied means every packet is denied.
	VerdictDenied
	// VerdictPartial means some packets are permitted and others denied.
	VerdictPartial
	// VerdictIndeterminate means at least one packet's fate depends on
	// something that cannot be evaluated offline.
	VerdictIndeterminate
)

// String returns the verdict name.
func (v Verdict) String() string {
	switch v {
	case VerdictUnset:
		return "unset"
	case VerdictAllowed:
		return "allowed"
	case VerdictDenied:
		return "denied"
	case VerdictPartial:
		return "partial"
	case VerdictIndeterminate:
		return "indeterminate"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (v Verdict) MarshalText() ([]byte, error) { return []byte(v.String()), nil }

// Outcome classifies one decided piece of a path.
type Outcome uint8

// Outcomes.
const (
	OutcomeUnset Outcome = iota
	// OutcomePermit means a permit rule or a permitting default matched.
	OutcomePermit
	// OutcomeDeny means a deny rule matched.
	OutcomeDeny
	// OutcomeDefault means no rule matched and the default action denied.
	OutcomeDefault
	// OutcomeUnknown means an undecidable rule might have matched first,
	// or the zones or budget did not allow a decision.
	OutcomeUnknown
)

// String returns the outcome name.
func (o Outcome) String() string {
	switch o {
	case OutcomeUnset:
		return "unset"
	case OutcomePermit:
		return "permit"
	case OutcomeDeny:
		return "deny"
	case OutcomeDefault:
		return "default-deny"
	case OutcomeUnknown:
		return "unknown"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (o Outcome) MarshalText() ([]byte, error) { return []byte(o.String()), nil }

// Decision is the part of a path one rule, or the default action, decides.
// Spaces are in policy terms: the addresses the rules match.
type Decision struct {
	// Rule is nil for the default action.
	Rule    *firemon.Rule
	Outcome Outcome
	Space   traffic.Region
	// Possible lists undecidable rules that might have matched this space
	// before Rule did.
	Possible []*firemon.Rule
	// Final is the outcome Rule (or the default action) gives. It equals
	// Outcome unless a possible rule with a different action makes the
	// outcome unknown.
	Final Outcome
}

// NATHit records a NAT rule applied on a path.
type NATHit struct {
	Rule   *firemon.NATRule       // nil for static NAT
	Static *firemon.StaticMapping // nil for dynamic NAT
	// Translated is the rewritten address set.
	Translated traffic.AddressSet
}

// Path is the part of a request that crosses the firewall between one
// pair of zones with the same NAT treatment.
type Path struct {
	From    string
	To      string
	Ingress string
	Egress  string
	// Original is the requested traffic on this path before NAT.
	Original traffic.Space
	// Policy is the same traffic as the security rules see it.
	Policy traffic.Space
	// DestinationNAT and SourceNAT are the translations applied, if any.
	DestinationNAT *NATHit
	SourceNAT      []NATHit
	Decisions      []Decision
	Verdict        Verdict
	// Incomplete reports that the evaluation budget was exhausted.
	Incomplete bool
}

// Region returns the policy-space region with the given outcome.
func (p *Path) Region(o Outcome) traffic.Region {
	var out traffic.Region
	for _, d := range p.Decisions {
		if d.Outcome == o {
			out = out.Union(d.Space)
		}
	}
	return out
}

// Result is the evaluation of one request.
type Result struct {
	Request Request
	Paths   []Path
	// Unrouted is the destination part no route forwards.
	Unrouted traffic.AddressSet
	Verdict  Verdict
}

// verdictOf combines outcomes into a verdict.
func verdictOf(outcomes map[Outcome]bool) Verdict {
	switch {
	case outcomes[OutcomeUnknown]:
		return VerdictIndeterminate
	case outcomes[OutcomePermit] && (outcomes[OutcomeDeny] || outcomes[OutcomeDefault]):
		return VerdictPartial
	case outcomes[OutcomePermit]:
		return VerdictAllowed
	case outcomes[OutcomeDeny] || outcomes[OutcomeDefault]:
		return VerdictDenied
	default:
		return VerdictUnset
	}
}

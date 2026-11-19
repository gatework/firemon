package converge

import (
	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
)

// Category classifies a finding.
type Category uint8

// Categories, in report order.
const (
	CategoryUnset Category = iota
	// CategoryUnusedObject: an object nothing live references.
	CategoryUnusedObject
	// CategoryEmptyObject: an object without entries or members.
	CategoryEmptyObject
	// CategoryNeverMatches: a rule whose match is empty.
	CategoryNeverMatches
	// CategoryIncomplete: a rule the device ignores.
	CategoryIncomplete
	// CategoryDisabled: a disabled rule.
	CategoryDisabled
	// CategoryExpired: a rule whose validity ended.
	CategoryExpired
	// CategoryRedundant: a rule fully covered by earlier rules of the same
	// action.
	CategoryRedundant
	// CategoryShadowed: a rule fully covered by earlier rules, one of them
	// of the opposite action: the rule's intent never takes effect.
	CategoryShadowed
	// CategoryMergeable: rules equal in two dimensions that can become one.
	CategoryMergeable
	// CategoryBroad: a permit wider than a reviewed rule usually is.
	CategoryBroad
	// CategoryZeroHit: a rule without hits over the observation window.
	CategoryZeroHit
	// CategoryDuplicateObject: objects of one kind with equal contents
	// under different names; rules could refer to one of them.
	CategoryDuplicateObject
	// CategoryNoLog: a permit rule that logs nothing; its traffic leaves
	// no trace for audits and troubleshooting.
	CategoryNoLog
)

// String returns the category name.
func (c Category) String() string {
	switch c {
	case CategoryUnset:
		return "unset"
	case CategoryUnusedObject:
		return "unused-object"
	case CategoryEmptyObject:
		return "empty-object"
	case CategoryNeverMatches:
		return "never-matches"
	case CategoryIncomplete:
		return "incomplete"
	case CategoryDisabled:
		return "disabled"
	case CategoryExpired:
		return "expired"
	case CategoryRedundant:
		return "redundant"
	case CategoryShadowed:
		return "shadowed"
	case CategoryMergeable:
		return "mergeable"
	case CategoryBroad:
		return "broad"
	case CategoryZeroHit:
		return "zero-hit"
	case CategoryNoLog:
		return "no-log"
	case CategoryDuplicateObject:
		return "duplicate-object"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (c Category) MarshalText() ([]byte, error) { return []byte(c.String()), nil }

// Tier tells whether a finding can be planned as a change.
type Tier uint8

// Tiers.
const (
	TierUnset Tier = iota
	// TierSafe: a change that keeps the effective policy exists; Plan
	// designs and verifies it.
	TierSafe
	// TierReview: advice; acting on it changes the policy or needs evidence
	// the model lacks.
	TierReview
)

// String returns the tier name.
func (t Tier) String() string {
	switch t {
	case TierUnset:
		return "unset"
	case TierSafe:
		return "safe"
	case TierReview:
		return "review"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (t Tier) MarshalText() ([]byte, error) { return []byte(t.String()), nil }

// Evidence names what a finding rests on.
type Evidence uint8

// Evidence kinds.
const (
	EvidenceUnset Evidence = iota
	// EvidenceStatic: the configuration alone.
	EvidenceStatic
	// EvidenceHits: the rule hit counters.
	EvidenceHits
	// EvidenceBoth: the configuration and the counters agree.
	EvidenceBoth
)

// String returns the evidence name.
func (e Evidence) String() string {
	switch e {
	case EvidenceUnset:
		return "unset"
	case EvidenceStatic:
		return "static"
	case EvidenceHits:
		return "hits"
	case EvidenceBoth:
		return "static+hits"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (e Evidence) MarshalText() ([]byte, error) { return []byte(e.String()), nil }

// Reason refines a finding for the operator.
type Reason uint8

// Reasons.
const (
	ReasonUnset Reason = iota
	// ReasonSourceAny, ReasonDestinationAny, ReasonServiceAny,
	// ReasonZoneAny: a dimension of a broad permit is any.
	ReasonSourceAny
	ReasonDestinationAny
	ReasonServiceAny
	ReasonZoneAny
	// ReasonWideSource, ReasonWideDestination: a /16 or wider subnet.
	ReasonWideSource
	ReasonWideDestination
	// ReasonVeryWide: a /8 or wider subnet.
	ReasonVeryWide
	// ReasonNoHits, ReasonHits: what the counters say about a broad rule.
	ReasonNoHits
	ReasonHits
	// ReasonCountersReset: the counter window is shorter than asked.
	ReasonCountersReset
)

// String returns the reason name.
func (r Reason) String() string {
	switch r {
	case ReasonUnset:
		return "unset"
	case ReasonSourceAny:
		return "source-any"
	case ReasonDestinationAny:
		return "destination-any"
	case ReasonServiceAny:
		return "service-any"
	case ReasonZoneAny:
		return "zone-any"
	case ReasonWideSource:
		return "wide-source"
	case ReasonWideDestination:
		return "wide-destination"
	case ReasonVeryWide:
		return "very-wide"
	case ReasonNoHits:
		return "no-hits"
	case ReasonHits:
		return "hits"
	case ReasonCountersReset:
		return "counters-reset"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (r Reason) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

// Merge describes a mergeable group: the first rule absorbs the others in
// Field, and the others go.
type Merge struct {
	Keep   string       `json:"keep"`
	Remove []string     `json:"remove"`
	Field  design.Field `json:"field"`
}

// Finding is one review result.
type Finding struct {
	// ID identifies the finding for selection, stable for one
	// configuration: category and subject.
	ID       string              `json:"id"`
	Category Category            `json:"category"`
	Tier     Tier                `json:"tier"`
	Evidence Evidence            `json:"evidence"`
	Rules    []string            `json:"rules,omitempty"`
	Objects  []firemon.ObjectRef `json:"objects,omitempty"`
	By       []string            `json:"by,omitempty"`
	Reasons  []Reason            `json:"reasons,omitempty"`
	Merge    *Merge              `json:"merge,omitempty"`
	Detail   string              `json:"detail,omitempty"`
}

package firemon

import "strings"

// IssueKind classifies why something cannot be evaluated exactly.
type IssueKind uint8

// Issue kinds.
const (
	IssueKindUnset IssueKind = iota
	// IssueKindObject is an unknown, invalid, cyclic or dynamic object.
	IssueKindObject
	// IssueKindDomain is a domain name the rule matches by name, outside
	// its destination (or negated), so no target decides it.
	IssueKindDomain
	// IssueKindDestinationDomain is a destination domain name: a target
	// that names its domain decides it.
	IssueKindDestinationDomain
	// IssueKindApplication is application matching: a target that names
	// its application decides it.
	IssueKindApplication
	// IssueKindUser is user or user-group matching.
	IssueKindUser
	// IssueKindURLCategory is URL category matching.
	IssueKindURLCategory
	// IssueKindSchedule is an unknown or unsupported schedule.
	IssueKindSchedule
	// IssueKindZone is an unknown zone.
	IssueKindZone
	// IssueKindAction is an unknown action.
	IssueKindAction
	// IssueKindUnsupported is any other criterion the model cannot
	// evaluate, or a line the parser could not read.
	IssueKindUnsupported
	// IssueKindConfig is a configuration fact reported for review, such as
	// an incomplete rule or an uninstalled route.
	IssueKindConfig
)

// String returns the kind name.
func (k IssueKind) String() string {
	switch k {
	case IssueKindUnset:
		return "unset"
	case IssueKindObject:
		return "object"
	case IssueKindDomain:
		return "domain"
	case IssueKindDestinationDomain:
		return "destination-domain"
	case IssueKindApplication:
		return "application"
	case IssueKindUser:
		return "user"
	case IssueKindURLCategory:
		return "url-category"
	case IssueKindSchedule:
		return "schedule"
	case IssueKindZone:
		return "zone"
	case IssueKindAction:
		return "action"
	case IssueKindUnsupported:
		return "unsupported"
	case IssueKindConfig:
		return "config"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (k IssueKind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// Issue is something compilation could not evaluate exactly, or a
// configuration fact worth reviewing.
type Issue struct {
	Kind   IssueKind `json:"kind"`
	Object string    `json:"object,omitempty"`
	Reason string    `json:"reason"`
}

// String writes "object: reason".
func (i Issue) String() string {
	if i.Object == "" {
		return i.Reason
	}
	return i.Object + ": " + i.Reason
}

// issuesOf wraps reasons as issues of one kind.
func issuesOf(kind IssueKind, reasons []string) []Issue {
	out := make([]Issue, len(reasons))
	for i, r := range reasons {
		out[i] = Issue{Kind: kind, Reason: r}
	}
	return out
}

// unsupportedKind classifies a criterion a parser recognized but the
// model cannot evaluate (SecurityRule.Unsupported).
func unsupportedKind(criterion string) IssueKind {
	switch {
	case strings.HasPrefix(criterion, "source-user"), strings.HasPrefix(criterion, "user"),
		strings.HasPrefix(criterion, "role"):
		return IssueKindUser
	case strings.HasPrefix(criterion, "category"), strings.HasPrefix(criterion, "url-category"):
		return IssueKindURLCategory
	case strings.HasPrefix(criterion, "domain-book"):
		return IssueKindDomain
	default:
		return IssueKindUnsupported
	}
}

// unsupportedIssues classifies parser criteria.
func unsupportedIssues(criteria []string) []Issue {
	out := make([]Issue, len(criteria))
	for i, c := range criteria {
		out[i] = Issue{Kind: unsupportedKind(c), Reason: c}
	}
	return out
}

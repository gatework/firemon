package query

import (
	"errors"
	"net/netip"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// ErrEmptyRequest reports a request without sources, destinations or services.
var ErrEmptyRequest = errors.New("query: empty request")

// Request is the traffic to evaluate.
type Request struct {
	Src     traffic.AddressSet
	Dst     traffic.AddressSet
	Service traffic.ServiceSet
	// At is the instant schedules are evaluated at; zero means Options.Now.
	At time.Time
	// VirtualRouter selects the routing context; empty means the vendor
	// default.
	VirtualRouter string
	// FromZone and ToZone override zone discovery by routing, for transparent
	// (layer-2) deployments and for asking about one zone pair.
	FromZone string
	ToZone   string
	// DstDomains are destination domain names. Rules match them by their
	// domain patterns; rules written with addresses only match them through
	// Resolved, or are possible matches when the name is not resolved.
	// Unresolved names leave through the default route.
	DstDomains []string
	// Resolved maps a domain name to its addresses, when known.
	Resolved map[string][]netip.Addr
	// Applications are application names. Rules restricted to other
	// applications do not match; with Service any, the application's
	// default ports are evaluated.
	Applications []string
	// Strict keeps rules by application, user and URL category possible
	// matches when the request does not give those criteria, the
	// conservative reading of ADR 0016. By default the request is taken to be the
	// standard application of its ports (tcp/22 is SSH): rules restricted
	// to other applications do not match, and each path records the
	// application it assumed.
	Strict bool
	// Users are the users, groups or roles the source is known to be. Rules
	// that match by user are matched against them; with none given they are
	// taken not to match, a premise every path records.
	Users []string
	// URLCategories are the URL categories of the request, matched the same
	// way. Rules by URL category never match traffic identified as an
	// application that is not web traffic.
	URLCategories []string
}

// Space returns the request as one traffic space.
func (r Request) Space() traffic.Space {
	return traffic.Space{Src: r.Src, Dst: r.Dst, Service: r.Service}
}

// empty reports whether the request has nothing to evaluate.
func (r Request) empty() bool {
	return (r.Src.IsEmpty() || r.Service.IsEmpty()) || (r.Dst.IsEmpty() && len(r.DstDomains) == 0)
}

// Options configures an Engine. The zero value uses time.Now and a budget
// of DefaultMaxSpaces.
type Options struct {
	// Now supplies the evaluation instant when a request leaves At zero.
	Now func() time.Time
	// MaxSpaces bounds the number of disjoint spaces tracked per path.
	MaxSpaces int
	// MaxPaths bounds the number of paths one query evaluates.
	MaxPaths int
	// Schedules selects how rules with schedules or validity windows count.
	Schedules ScheduleMode
	// Activity tells, under ScheduleWorstCase, how each timed rule behaves
	// over the evaluated period. Nil, or a rule it does not know, is
	// ActivityPartial.
	Activity func(*firemon.Rule) Activity
}

// ScheduleMode tells how scheduled rules take part in evaluation.
type ScheduleMode uint8

// Schedule modes.
const (
	// ScheduleAt evaluates schedules at the request instant.
	ScheduleAt ScheduleMode = iota
	// ScheduleAlwaysActive treats every unexpired scheduled rule as active,
	// for checking access that is itself scheduled.
	ScheduleAlwaysActive
	// ScheduleNeverActive ignores scheduled rules, for checking permanent
	// access: a rule that permits only part of the time does not count.
	ScheduleNeverActive
	// ScheduleWorstCase reads each timed rule by Options.Activity over the
	// period access must hold: a rule in force throughout is active, one
	// never in force is inactive, and one in force only part of the time
	// counts against the traffic: a deny is active, any other rule is not.
	ScheduleWorstCase
)

// Activity is how a timed rule behaves over an evaluated period.
type Activity uint8

// Activities.
const (
	// ActivityPartial: in force for part of the period, or not provably
	// either way.
	ActivityPartial Activity = iota
	// ActivityAlways: in force throughout the period.
	ActivityAlways
	// ActivityNever: never in force during the period.
	ActivityNever
)

// Default evaluation budgets.
const (
	DefaultMaxSpaces = 20000
	DefaultMaxPaths  = 4096
)

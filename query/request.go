package query

import (
	"errors"
	"net/netip"
	"time"

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
)

// Default evaluation budgets.
const (
	DefaultMaxSpaces = 20000
	DefaultMaxPaths  = 4096
)

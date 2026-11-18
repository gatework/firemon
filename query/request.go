package query

import (
	"errors"
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
}

// Space returns the request as one traffic space.
func (r Request) Space() traffic.Space {
	return traffic.Space{Src: r.Src, Dst: r.Dst, Service: r.Service}
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
}

// Default evaluation budgets.
const (
	DefaultMaxSpaces = 20000
	DefaultMaxPaths  = 4096
)

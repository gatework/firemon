package design

import (
	"time"

	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// Intent is the access to permit.
type Intent struct {
	Src     traffic.AddressSet
	Dst     traffic.AddressSet
	Service traffic.ServiceSet
	// FromZone, ToZone and VirtualRouter steer path discovery as in
	// query.Request.
	FromZone      string
	ToZone        string
	VirtualRouter string
	// Name names new rules; Description is copied to them.
	Name        string
	Description string
	// Schedule names an existing schedule to attach to new rules.
	Schedule string
	// Override places new rules above specific deny rules that block the
	// intent instead of reporting them as conflicts.
	Override bool
	// NAT asks for a translation with the access; nil plans access only.
	NAT *NATIntent
}

func (i Intent) request(at time.Time) query.Request {
	return query.Request{
		Src: i.Src, Dst: i.Dst, Service: i.Service, At: at,
		FromZone: i.FromZone, ToZone: i.ToZone, VirtualRouter: i.VirtualRouter,
	}
}

// Options configures a Planner. The zero value uses DefaultNaming,
// time.Now and groups of DefaultGroupThreshold objects.
type Options struct {
	Naming Naming
	Now    func() time.Time
	// GroupThreshold is the number of objects in one field of a new or
	// extended rule from which they are aggregated into a group; negative
	// disables grouping.
	GroupThreshold int
}

// DefaultGroupThreshold aggregates three or more objects into a group.
const DefaultGroupThreshold = 3

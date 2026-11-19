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
	// OverrideNAT publishes a new NAT rule in front of one that already
	// publishes the same public address and port to another server. It is
	// separate from Override: taking an address over is never implied.
	OverrideNAT bool
	// NAT asks for a translation with the access; nil plans access only.
	NAT *NATIntent
	// NoLog leaves new rules without logging; by default they log the
	// session at start and end.
	NoLog bool
	// LogSetting names the log forwarding profile of new rules (PAN-OS).
	LogSetting string
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

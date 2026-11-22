package design

import (
	"fmt"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/query"
)

// verifyAccess checks on a final configuration that an access proof still
// holds: each zone pair the plan opened permits what it opened and keeps
// its conflicts closed, and a full proof needs the whole request allowed.
// The planner must be built on after; at is the instant of the proof.
func (p *Planner) verifyAccess(after *firemon.Firewall, claim accessProof, at time.Time) error {
	res, err := p.engine(after, claim.intent).Query(claim.intent.request(at))
	if err != nil {
		return err
	}
	if claim.full && res.Verdict != query.VerdictAllowed {
		return fmt.Errorf("%w: request is no longer fully permitted", ErrPlanChanged)
	}
	for _, n := range claim.opened {
		permitted := permittedOn(res, n.from, n.to)
		if !n.region.SubtractRegion(permitted).IsEmpty() {
			return fmt.Errorf("%w on %s -> %s", ErrNeedNotOpened, n.from, n.to)
		}
		for _, s := range n.conflict.Spaces() {
			if !permitted.Intersect(s).IsEmpty() {
				return fmt.Errorf("%w on %s -> %s", ErrConflictOpened, n.from, n.to)
			}
		}
	}
	return nil
}

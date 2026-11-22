package design

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// ErrPlanChanged reports that the baseline, intended scope or resulting
// configuration differs from what the planner verified.
var ErrPlanChanged = errors.New("design: plan differs from its verified scope")

// planPart binds the result of one planning operation to its baseline and
// request. A later part may rely on objects or rules created by an earlier one.
type planPart struct {
	intent        Intent
	before, after string
	verified      bool
	nat           *NATIntent
	block         *traffic.Space
}

type accessProof struct {
	intent Intent
	opened []need
	full   bool
}

func (p *Plan) recordPart(fw *firemon.Firewall, in Intent) error {
	claim := planPart{intent: cloneIntent(in), before: fw.Fingerprint(), after: fw.Fingerprint(), verified: p.Verified}
	if p.Verified && p.NAT != nil && (p.NAT.Status == NATStatusAdded || p.NAT.Status == NATStatusSatisfied) {
		nat := *in.NAT
		// Keep the address chosen during planning, including an automatically
		// reused address. A later lookup must prove that same translation.
		if p.NAT.Address != "" {
			addr, err := netip.ParseAddr(p.NAT.Address)
			if err != nil {
				return fmt.Errorf("design: recorded NAT address: %w", err)
			}
			nat.Address = addr
		}
		claim.nat = &nat
	}
	if len(p.Changes) > 0 {
		claim.after = ""
		if p.Verified {
			after, err := p.appliedTo(fw)
			if err != nil {
				return err
			}
			claim.after = after.Fingerprint()
		}
	}
	p.parts = []planPart{claim}
	return nil
}

func cloneIntent(in Intent) Intent {
	if in.NAT != nil {
		nat := *in.NAT
		in.NAT = &nat
	}
	return in
}

func sameIntent(a, b Intent) bool {
	if a.NAT != nil && b.NAT != nil {
		if *a.NAT != *b.NAT {
			return false
		}
	} else if a.NAT != b.NAT {
		return false
	}
	return a.Src.Equal(b.Src) && a.Dst.Equal(b.Dst) && a.Service.Equal(b.Service) &&
		a.FromZone == b.FromZone && a.ToZone == b.ToZone && a.VirtualRouter == b.VirtualRouter &&
		a.Name == b.Name && a.Description == b.Description && a.Schedule == b.Schedule &&
		a.Override == b.Override && a.OverrideNAT == b.OverrideNAT && a.NoLog == b.NoLog && a.LogSetting == b.LogSetting &&
		a.Until.Equal(b.Until) && a.Strict == b.Strict && slices.Equal(a.Users, b.Users) && slices.Equal(a.URLCategories, b.URLCategories)
}

func (p *Plan) appliedTo(fw *firemon.Firewall) (*firemon.Firewall, error) {
	cfg := fw.Config()
	if err := Apply(cfg, p.Changes); err != nil {
		return nil, err
	}
	return firemon.Compile(cfg)
}

// VerifyParts replays a combined access plan from the original firewall and
// checks every supplied part on the final configuration, including NAT and time
// restrictions. Independent verified changes can coexist with reported gaps.
func VerifyParts(fw *firemon.Firewall, plan *Plan, parts []Intent, at time.Time) error {
	if plan == nil {
		return ErrPlanChanged
	}
	err := plan.verifyParts(fw, parts, at)
	plan.Verified = err == nil
	plan.VerifyError = ""
	if err != nil {
		plan.VerifyError = err.Error()
	}
	return err
}

func (p *Plan) verifyParts(fw *firemon.Firewall, parts []Intent, at time.Time) error {
	if len(parts) != len(p.parts) {
		return fmt.Errorf("%w: different number of request parts", ErrPlanChanged)
	}
	for i, in := range parts {
		if !sameIntent(in, p.parts[i].intent) {
			return fmt.Errorf("%w: request part %d", ErrPlanChanged, i+1)
		}
	}
	return p.VerifyBefore(fw, at)
}

// VerifyBefore checks the immutable scopes and planned result against a fresh
// baseline. It is safe to call concurrently and does not alter the plan.
func (p *Plan) VerifyBefore(fw *firemon.Firewall, at time.Time) error {
	if p.Kind == PlanKindCleanup && p.cleanup != nil && fw.Fingerprint() == p.Baseline {
		after, err := p.appliedTo(fw)
		if err != nil {
			return err
		}
		if err := p.VerifyResult(after, at); err != nil {
			return err
		}
		return p.cleanup.verify(fw, after, at)
	}
	if p.Kind != PlanKindAccess || len(p.parts) == 0 || p.Baseline != fw.Fingerprint() || !sameIntent(p.Intent, p.parts[0].intent) {
		return ErrPlanChanged
	}
	next := p.Baseline
	for _, part := range p.parts {
		if !part.verified || part.before != next || part.after == "" {
			return fmt.Errorf("%w: request parts have different baselines", ErrPlanChanged)
		}
		next = part.after
	}
	after, err := p.appliedTo(fw)
	if err != nil {
		return err
	}
	return p.VerifyResult(after, at)
}

// VerifyResult checks the observed final configuration and each proved scope.
func (p *Plan) VerifyResult(after *firemon.Firewall, at time.Time) error {
	if p.Kind == PlanKindCleanup && p.cleanup != nil {
		if after.Fingerprint() != p.cleanup.expected {
			return ErrPlanChanged
		}
		return nil
	}
	if len(p.parts) == 0 || after.Fingerprint() != p.parts[len(p.parts)-1].after {
		return ErrPlanChanged
	}
	planner := New(after, Options{Now: func() time.Time { return at }})
	for _, claim := range p.access {
		if err := planner.verifyAccess(after, claim, at); err != nil {
			return err
		}
	}
	for _, part := range p.parts {
		if part.block != nil {
			open, _, err := blocked(after, *part.block, at, part.intent.Schedule)
			if err != nil {
				return err
			}
			if open {
				return ErrNotBlocked
			}
		}
		if part.nat != nil {
			in := part.intent
			in.NAT = part.nat
			out, _, _ := planner.planNAT(in, at)
			if out.Status != NATStatusSatisfied {
				return fmt.Errorf("%w: NAT %s", ErrPlanChanged, out.Status)
			}
		}
	}
	return nil
}

type cleanupProof struct {
	expected string
	verify   func(before, after *firemon.Firewall, at time.Time) error
}

// NewCleanupPlan verifies cleanup changes and binds the result to both the
// expected configuration and the policy comparison used by convergence.
func NewCleanupPlan(fw *firemon.Firewall, changes []Change, at time.Time, verify func(before, after *firemon.Firewall, at time.Time) error) (*Plan, error) {
	p := &Plan{Kind: PlanKindCleanup, Baseline: fw.Fingerprint(), Status: StatusChange, Changes: changes}
	if verify == nil {
		return nil, fmt.Errorf("%w: missing cleanup verification", ErrPlanChanged)
	}
	if len(changes) == 0 {
		p.Status, p.Verified = StatusNoChange, true
		return p, nil
	}
	// A failed proof is part of the plan, not an error: the plan is
	// returned unverified with the reason.
	after, err := p.appliedTo(fw)
	if err == nil {
		err = verify(fw, after, at)
	}
	if err == nil {
		p.cleanup = &cleanupProof{expected: after.Fingerprint(), verify: verify}
	}
	p.Verified, p.VerifyError = err == nil, errorText(err)
	return p, nil
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

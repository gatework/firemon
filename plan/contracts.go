// Package plan selects deterministic, renderable policy changes with exact traffic proofs.
package plan

import (
	"context"
	"errors"
	"slices"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/policy"
)

var ErrUnsafe = errors.New("no proven renderable policy plan")

type ChangeKind uint8

const (
	AppendMembers ChangeKind = iota + 1
	CreateRule
	RemoveRule
)

type Change struct {
	Kind                  ChangeKind
	Rule                  fm.ID
	Sources, Destinations []fm.AddressRef
	Services              []fm.ServiceRef
}

type Cost struct {
	NewRules, AppendedMembers, NewObjects, ModifiedRules, Moves, Position int
	ID                                                                    string
}

type Proof struct {
	BaseDigest, ResultDigest                      string
	TargetAllowed, OutsidePreserved, NATUnchanged bool
	TargetSatisfied                               bool
}

type Plan struct {
	before, after *fm.Firewall
	changes       []Change
	commands      []string
	cost          Cost
	proof         Proof
	digest        string
	target        policy.Request
	engine        policy.Engine
	preservation  *policy.Equivalence
	transfers     []RuleIntent
	transferFrom  time.Time
}

type Renderer interface {
	Render(context.Context, *fm.Firewall, *fm.Firewall, []Change) ([]string, error)
}

func (c Cost) less(b Cost) bool {
	aValues := []int{c.NewRules, c.AppendedMembers, c.NewObjects, c.ModifiedRules, c.Moves, c.Position}
	bValues := []int{b.NewRules, b.AppendedMembers, b.NewObjects, b.ModifiedRules, b.Moves, b.Position}
	for i, a := range aValues {
		if a != bValues[i] {
			return a < bValues[i]
		}
	}
	return c.ID < b.ID
}

func (p *Plan) Before() *fm.Firewall { return p.before }

func (p *Plan) After() *fm.Firewall { return p.after }

func (p *Plan) Changes() []Change {
	out := slices.Clone(p.changes)
	for i := range out {
		out[i].Sources = slices.Clone(out[i].Sources)
		out[i].Destinations = slices.Clone(out[i].Destinations)
		out[i].Services = slices.Clone(out[i].Services)
	}
	return out
}

func (p *Plan) Commands() []string { return slices.Clone(p.commands) }

func (p *Plan) Cost() Cost { return p.cost }

func (p *Plan) Proof() Proof { return p.proof }

func (p *Plan) Digest() string { return p.digest }

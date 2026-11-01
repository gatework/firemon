package inventory

import (
	"context"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// Topology is external business evidence, independent of route reachability.
// Every binding is pinned to the immutable snapshot it describes.
type Topology struct {
	Version  int       `json:"version"`
	Bindings []Binding `json:"bindings"`
}
type Role string

const (
	Protection Role = "protection"
	Ingress    Role = "ingress"
)

type View string

const (
	Original   View = "original"
	Real       View = "real"
	Translated View = "translated"
)

type Binding struct {
	Device   string              `json:"device"`
	Revision string              `json:"revision"`
	Scope    string              `json:"scope"`
	VRF      string              `json:"vrf"`
	Zone     fm.ID               `json:"zone"`
	Role     Role                `json:"role"`
	View     View                `json:"view"`
	Networks []flow.AddressRange `json:"networks"`
	Sources  []string            `json:"sources,omitempty"`
}

// Nil scope/VRF matches all contexts; a pointer to empty selects the default.
type Selection struct {
	Device     string
	Scope, VRF *string
	Role       Role
	View       View
}
type Location struct {
	Addresses flow.AddressSet
	Bindings  []Binding
}

func (t Topology) Validate() error {
	if t.Version != 1 || len(t.Bindings) > 4096 {
		return ErrInvalid
	}
	total := 0
	for _, b := range t.Bindings {
		total += len(b.Networks)
		if b.Device == "" || b.Revision == "" || b.Zone == "" || len(b.Networks) == 0 || total > 4096 || (b.Role != Protection && b.Role != Ingress) || (b.View != Original && b.View != Real && b.View != Translated) {
			return ErrInvalid
		}
		if _, err := flow.NewAddressSet(b.Networks...); err != nil {
			return err
		}
	}
	return nil
}

// Locate partitions intervals by all matching bindings, retaining empty and
// overlapping ownership. Neither longest-prefix preference nor routes break ties.
func (t Topology) Locate(ctx context.Context, addresses flow.AddressSet, q Selection, limit int) ([]Location, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	if limit < 1 || len(addresses.Ranges()) > limit {
		return nil, flow.ErrBudget
	}
	parts := []Location{{Addresses: addresses}}
	visits := 0
	for _, b := range t.Bindings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if b.Role != q.Role || b.View != q.View || q.Device != "" && b.Device != q.Device || q.Scope != nil && b.Scope != *q.Scope || q.VRF != nil && b.VRF != *q.VRF {
			continue
		}
		set, _ := flow.NewAddressSet(b.Networks...)
		var next []Location
		ranges := 0
		for _, p := range parts {
			visits++
			if visits > 100000 {
				return nil, flow.ErrBudget
			}
			hit := p.Addresses.Intersection(set)
			rest := p.Addresses.Difference(set)
			if !rest.Empty() {
				next = append(next, Location{rest, p.Bindings})
			}
			if !hit.Empty() {
				copyBinding := b
				copyBinding.Networks = slices.Clone(b.Networks)
				copyBinding.Sources = slices.Clone(b.Sources)
				next = append(next, Location{hit, append(slices.Clone(p.Bindings), copyBinding)})
			}
			ranges += len(rest.Ranges()) + len(hit.Ranges())
			if ranges > limit {
				return nil, flow.ErrBudget
			}
		}
		parts = next
	}
	return parts, ctx.Err()
}

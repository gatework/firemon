package inventory

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
)

// Applied returns the inventory as it will be once the verified plans are
// deployed: every member of a planned cluster takes the plan's changes, as
// HA synchronization gives them. Requests answered one after another (a
// batch of tickets) are each designed on the changes before them, so
// objects are reused and rule IDs do not collide.
func (inv *Inventory) Applied(plans []ClusterPlan) (*Inventory, error) {
	members := slices.Clone(inv.given)
	for _, cp := range plans {
		if cp.Plan == nil || !cp.Plan.Verified || len(cp.Plan.Changes) == 0 {
			continue
		}
		for i, m := range members {
			if cmp.Or(m.Cluster, m.Name) != cp.Cluster {
				continue
			}
			cfg := m.Firewall.Config()
			if err := design.Apply(cfg, cp.Plan.Changes); err != nil {
				return nil, fmt.Errorf("inventory: %s: %w", m.Name, err)
			}
			fw, err := firemon.Compile(cfg)
			if err != nil {
				return nil, fmt.Errorf("inventory: %s: %w", m.Name, err)
			}
			members[i].Firewall = fw
		}
	}
	return New(members, inv.opts)
}

package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/adapter/filestore"
	"github.com/gatework/firemon/adapter/yamlfile"
	"github.com/gatework/firemon/internal/bootstrap"
	"github.com/gatework/firemon/internal/workflow"
	"github.com/gatework/firemon/inventory"
)

type fleetMember struct {
	name, cluster, snapshot string
	active                  bool
}

// inventory loads the fleet: the firewalls of --inventory with their
// clusters and protected networks, or every stored snapshot.
func (o *options) inventory(cmd *cobra.Command) (*inventory.Inventory, map[string]bootstrap.Platform, error) {
	store, err := filestore.New(o.store)
	if err != nil {
		return nil, nil, err
	}
	fleet, protections, err := o.fleet(cmd, store)
	if err != nil {
		return nil, nil, err
	}
	var members []inventory.Member
	platforms := map[string]bootstrap.Platform{}
	for _, fm := range fleet {
		snap, err := store.Load(cmd.Context(), fm.snapshot)
		if err != nil {
			return nil, nil, fmt.Errorf("库存中的防火墙 %s：%w", fm.name, snapshotError(err, fm.snapshot, o.store))
		}
		loaded, err := workflow.FromConfig(snap.Config)
		if err != nil {
			return nil, nil, err
		}
		if platforms[fm.name], err = bootstrap.Lookup(snap.Vendor, snap.Config.Location, nil); err != nil {
			return nil, nil, err
		}
		members = append(members, inventory.Member{
			Name: fm.name, Cluster: fm.cluster, Firewall: loaded.Firewall, Naming: platforms[fm.name].Naming,
			Active: fm.active,
		})
	}
	inv, err := inventory.New(members, inventory.Options{Now: o.deps.Now, Protections: protections})
	return inv, platforms, err
}

func (o *options) fleet(cmd *cobra.Command, store *filestore.Store) ([]fleetMember, []inventory.Protection, error) {
	if o.inventoryFile != "" {
		f, err := yamlfile.Load(o.inventoryFile)
		if err != nil {
			return nil, nil, inventoryError(err, o.inventoryFile)
		}
		protections, err := f.Protections(cmd.Context())
		if err != nil {
			return nil, nil, err
		}
		out := make([]fleetMember, 0, len(f.Firewalls))
		for _, fw := range f.Firewalls {
			out = append(out, fleetMember{name: fw.Name, cluster: fw.Cluster, snapshot: fw.SnapshotOf(), active: fw.Active()})
		}
		return out, protections, nil
	}
	snaps, err := store.List(cmd.Context())
	if err != nil {
		return nil, nil, err
	}
	if len(snaps) == 0 {
		return nil, nil, errors.New("快照目录 " + o.store + " 中没有快照；请先用 collect 保存，或用 --inventory 指定库存文件")
	}
	out := make([]fleetMember, 0, len(snaps))
	for _, s := range snaps {
		out = append(out, fleetMember{name: s.Device, snapshot: s.Device})
	}
	return out, nil, nil
}

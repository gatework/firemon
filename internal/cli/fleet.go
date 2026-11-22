package cli

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/adapter/filestore"
	"github.com/gatework/firemon/adapter/yamlfile"
	"github.com/gatework/firemon/internal/bootstrap"
	"github.com/gatework/firemon/internal/workflow"
	"github.com/gatework/firemon/inventory"
)

type fleetMember struct {
	name, cluster, snapshot string
	host                    string
	active                  bool
}

// inventory loads the fleet: the firewalls of --inventory with their
// clusters and protected networks, or every stored snapshot.
func (o *options) inventory(cmd *cobra.Command) (*inventory.Inventory, map[string]bootstrap.Platform, error) {
	if isDir(o.inventoryFile) {
		return o.backupInventory(cmd, o.inventoryFile)
	}
	store, err := bootstrap.OpenSnapshots(o.store)
	if err != nil {
		return nil, nil, err
	}
	fleet, zones, err := o.fleet(cmd, store)
	if err != nil {
		return nil, nil, err
	}
	var members []inventory.Member
	platforms := map[string]bootstrap.Platform{}
	for _, fm := range fleet {
		snap, err := o.loadStored(cmd.Context(), store, fm.snapshot)
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
			Active: fm.active, Host: fm.host, Capabilities: platforms[fm.name].Capabilities,
		})
	}
	warnInventory(cmd.ErrOrStderr(), fleet, members, zones)
	inv, err := inventory.New(members, inventory.Options{Now: o.deps.Now, Zones: zones})
	return inv, platforms, err
}

// warnInventory points out inventory mistakes that make answers wrong
// without failing: a bound zone the firewall does not have, several active
// members in a cluster, members of a cluster that bind differently.
func warnInventory(w io.Writer, fleet []fleetMember, members []inventory.Member, zones []inventory.ZoneBinding) {
	fws := map[string]*firemon.Firewall{}
	for _, m := range members {
		fws[m.Name] = m.Firewall
	}
	byMember := map[string][]string{}
	for _, z := range zones {
		if fw := fws[z.Firewall]; fw != nil && z.Zone != "" {
			if _, ok := fw.Zone(z.Zone); !ok {
				fmt.Fprintf(w, "提示：库存中 %s 绑定的区域 %s 在其快照中不存在，按该区域判定的结论可能不准\n", z.Firewall, z.Zone)
			}
		}
		key := fmt.Sprintf("%s %v %v %v", z.Zone, z.Protected, z.Networks, z.Exclude)
		byMember[z.Firewall] = append(byMember[z.Firewall], key)
	}
	active := map[string][]string{}
	first := map[string]string{}
	for _, fm := range fleet {
		c := cmp.Or(fm.cluster, fm.name)
		if fm.active {
			active[c] = append(active[c], fm.name)
		}
		keys := slices.Sorted(slices.Values(byMember[fm.name]))
		sig := strings.Join(keys, ";")
		if prev, ok := first[c]; !ok {
			first[c] = fm.name
		} else if other := strings.Join(slices.Sorted(slices.Values(byMember[prev])), ";"); sig != other {
			fmt.Fprintf(w, "提示：集群 %s 的成员 %s 与 %s 的区域绑定不一致，按主成员的判定\n", c, fm.name, prev)
		}
	}
	for _, c := range slices.Sorted(maps.Keys(active)) {
		if len(active[c]) > 1 {
			fmt.Fprintf(w, "提示：集群 %s 有多个 active 成员（%s），按名称取第一个\n", c, strings.Join(active[c], "、"))
		}
	}
}

func (o *options) fleet(cmd *cobra.Command, store *filestore.Store) ([]fleetMember, []inventory.ZoneBinding, error) {
	if isDir(o.inventoryFile) {
		return nil, nil, &usageError{fmt.Errorf("--inventory %s 是配置备份目录：该命令需要库存文件（YAML）与快照目录", o.inventoryFile)}
	}
	if o.inventoryFile != "" {
		f, err := yamlfile.Load(o.inventoryFile)
		if err != nil {
			return nil, nil, inventoryError(err, o.inventoryFile)
		}
		zones, err := f.ZoneBindings()
		if err != nil {
			return nil, nil, err
		}
		out := make([]fleetMember, 0, len(f.Firewalls))
		for _, fw := range f.Firewalls {
			out = append(out, fleetMember{name: fw.Name, cluster: fw.Cluster, snapshot: fw.SnapshotOf(), active: fw.Active(), host: fw.Host})
		}
		return out, zones, nil
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

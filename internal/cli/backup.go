package cli

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/adapter/yamlfile"
	"github.com/gatework/firemon/internal/bootstrap"
	"github.com/gatework/firemon/internal/workflow"
	"github.com/gatework/firemon/inventory"
)

var (
	// backupFile is a backup "<name>-<IPv4>.txt"; the member is named
	// "<name>-<IPv4>", as snapshots and inventory files name it.
	backupFile = regexp.MustCompile(`^(.+)-(\d+\.\d+\.\d+\.\d+)\.txt$`)
	// haBase is the cluster part of "<base>-FW<nn>" or "<base>FW<nn>".
	haBase = regexp.MustCompile(`^(.+?)-?FW0*\d+$`)
	// haEnabled marks a configuration that runs HA.
	haEnabled = regexp.MustCompile(`(?m)^(ha cluster \d|set deviceconfig high-availability enabled yes)`)
)

// isDir reports whether path is a directory.
func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// backupMember is one firewall configuration of a backup directory.
type backupMember struct {
	name, file, host string
	loaded           workflow.Loaded
	platform         bootstrap.Platform
	ha               bool
}

// backupInventory builds the inventory from a configuration backup
// directory instead of the snapshot store: every Hillstone and PAN-OS
// configuration in it is a member. The configured inventory file (settings
// or $FIREMON_INVENTORY), when there is one, supplies clusters, active
// members and zone bindings for the firewalls it names; the others pair
// into HA clusters by name ("X-FW01" with "X-FW02") when their
// configuration runs HA, and own the networks their routes reach.
func (o *options) backupInventory(cmd *cobra.Command, dir string) (*inventory.Inventory, map[string]bootstrap.Platform, error) {
	members, err := o.backupMembers(cmd, dir)
	if err != nil {
		return nil, nil, err
	}
	topology, zones, err := o.backupTopology()
	if err != nil {
		return nil, nil, err
	}
	clusters := pairByName(members, topology)
	fleet := make([]fleetMember, 0, len(members))
	invMembers := make([]inventory.Member, 0, len(members))
	platforms := map[string]bootstrap.Platform{}
	described := 0
	for _, m := range members {
		fm := fleetMember{name: m.name, snapshot: m.name, cluster: clusters[m.name]}
		if fw, ok := topology[m.name]; ok {
			described++
			fm.active = fw.Active()
		}
		fleet = append(fleet, fm)
		platforms[m.name] = m.platform
		invMembers = append(invMembers, inventory.Member{
			Name: m.name, Cluster: fm.cluster, Firewall: m.loaded.Firewall, Naming: m.platform.Naming, Active: fm.active, Host: m.host, Capabilities: m.platform.Capabilities,
		})
	}
	// Bindings of firewalls the backup does not hold do not apply.
	zones = slices.DeleteFunc(zones, func(z inventory.ZoneBinding) bool { return !hasMember(members, z.Firewall) })
	p := &printer{w: cmd.ErrOrStderr()}
	p.f("提示：从备份目录 %s 载入 %d 台防火墙（%d 个集群）；库存文件描述其中 %d 台的区域绑定，其余按各自路由判定归属\n",
		dir, len(members), countClusters(fleet), described)
	if p.err != nil {
		return nil, nil, p.err
	}
	warnInventory(cmd.ErrOrStderr(), fleet, invMembers, zones)
	inv, err := inventory.New(invMembers, inventory.Options{Now: o.deps.Now, Zones: zones})
	return inv, platforms, err
}

// backupMembers parses every firewall configuration of dir, ordered by
// name. Files of other vendors (switches, controllers) are skipped.
func (o *options) backupMembers(cmd *cobra.Command, dir string) ([]backupMember, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, &usageError{fmt.Errorf("读取备份目录 %s 失败：%w", dir, err)}
	}
	book, err := o.serviceBook()
	if err != nil {
		return nil, err
	}
	var out []backupMember
	for _, e := range entries {
		m := backupFile.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		name := detectVendor(path)
		if name == "" {
			continue
		}
		v, err := vendor("--vendor", name)
		if err != nil {
			continue
		}
		zone := o.timezone
		if o.timezoneDefault {
			zone = cmp.Or(deviceTimezone(path), zone)
		}
		loc, err := time.LoadLocation(zone)
		if err != nil {
			return nil, &usageError{fmt.Errorf("--timezone %q 不是有效的时区：请用 IANA 名称，例如 Asia/Shanghai", zone)}
		}
		p, err := bootstrap.Lookup(v, loc, book)
		if err != nil {
			return nil, err
		}
		loaded, err := workflow.Load(cmd.Context(), workflow.Source{Platform: p, File: path})
		if err != nil {
			return nil, fmt.Errorf("备份 %s 解析失败：%w", e.Name(), err)
		}
		out = append(out, backupMember{
			name: strings.TrimSuffix(e.Name(), ".txt"), file: path, host: m[2], loaded: loaded, platform: p,
			ha: haEnabled.MatchString(loaded.Raw),
		})
	}
	if len(out) == 0 {
		return nil, &usageError{fmt.Errorf("备份目录 %s 中没有 Hillstone 或 PAN-OS 的配置（文件名应为 <名称>-<IP>.txt）", dir)}
	}
	slices.SortFunc(out, func(a, b backupMember) int { return strings.Compare(a.name, b.name) })
	return out, nil
}

// backupTopology reads the configured inventory file, when it is a file,
// for the clusters, roles and zone bindings of the firewalls it names.
func (o *options) backupTopology() (map[string]yamlfile.Firewall, []inventory.ZoneBinding, error) {
	path := o.inventoryDefault
	if path == "" || isDir(path) {
		return nil, nil, nil
	}
	f, err := yamlfile.Load(path)
	if err != nil {
		return nil, nil, inventoryError(err, path)
	}
	zones, err := f.ZoneBindings()
	if err != nil {
		return nil, nil, err
	}
	out := make(map[string]yamlfile.Firewall, len(f.Firewalls))
	for _, fw := range f.Firewalls {
		out[fw.Name] = fw
	}
	return out, zones, nil
}

// pairByName returns each member's cluster: the inventory file's when it
// names the member, otherwise "<base>" shared by the HA members whose names
// differ only in the firewall number, otherwise none.
func pairByName(members []backupMember, topology map[string]yamlfile.Firewall) map[string]string {
	bases := map[string][]string{}
	for _, m := range members {
		if _, ok := topology[m.name]; ok || !m.ha {
			continue
		}
		host := strings.TrimSuffix(m.name, "-"+m.host)
		if b := haBase.FindStringSubmatch(host); b != nil {
			bases[b[1]] = append(bases[b[1]], m.name)
		}
	}
	out := map[string]string{}
	for base, names := range bases {
		if len(names) < 2 {
			continue
		}
		for _, n := range names {
			out[n] = base
		}
	}
	for name, fw := range topology {
		out[name] = fw.Cluster
	}
	return out
}

func hasMember(members []backupMember, name string) bool {
	return slices.ContainsFunc(members, func(m backupMember) bool { return m.name == name })
}

func countClusters(fleet []fleetMember) int {
	seen := map[string]bool{}
	for _, fm := range fleet {
		seen[cmp.Or(fm.cluster, fm.name)] = true
	}
	return len(seen)
}

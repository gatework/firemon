package cli

import (
	"runtime"
	"sync"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/internal/bootstrap"
	"github.com/gatework/firemon/inventory"
)

// fleetCluster is one cluster of the fleet as reviewed: the member it is
// evaluated on, with its platform, and every member named for operators.
type fleetCluster struct {
	Name     string
	Firewall *firemon.Firewall
	Platform bootstrap.Platform
	Devices  []inventory.Device // the evaluated member first
}

// Label names the cluster by its evaluated member.
func (c fleetCluster) Label() string {
	if len(c.Devices) > 0 {
		return c.Devices[0].Label()
	}
	return c.Name
}

// fleetClusters loads the fleet of --inventory, a backup directory or an
// inventory file with its snapshots, one entry per cluster in name order;
// only names the clusters to keep when not empty.
func (o *options) fleetClusters(cmd *cobra.Command, only []string) ([]fleetCluster, error) {
	inv, platforms, err := o.inventory(cmd)
	if err != nil {
		return nil, err
	}
	var out []fleetCluster
	for _, name := range inv.Clusters() {
		if len(only) > 0 && !containsFold(only, name) {
			continue
		}
		devices := inv.Devices(name)
		if len(devices) == 0 {
			continue
		}
		out = append(out, fleetCluster{Name: name, Firewall: inv.Firewall(name), Platform: platforms[devices[0].Name], Devices: devices})
	}
	return out, nil
}

// eachParallel runs work on every index, as many at once as there are
// CPUs; results go to their own index, so the order stays the input's.
func eachParallel(n int, work func(i int)) {
	sem := make(chan struct{}, max(1, runtime.GOMAXPROCS(0)))
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			work(i)
		}()
	}
	wg.Wait()
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if equalFold(x, s) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

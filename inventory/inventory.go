// Package inventory locates candidate firewalls using a revision-bound persisted manifest.
package inventory

import (
	"context"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/snapshot"
	"sort"
)

type Hit struct {
	Device, Revision string
	Addresses        flow.Set
}
type Result struct {
	Generation uint64
	Hits       []Hit
	Unknown    []string
	Complete   bool
}

func Locate(ctx context.Context, store *snapshot.Store, addresses flow.Set) (Result, error) {
	manifest, err := store.Manifest(ctx)
	if err != nil {
		return Result{}, err
	}
	result := Result{Generation: manifest.Generation, Complete: true}
	devices := make([]string, 0, len(manifest.Devices))
	for device := range manifest.Devices {
		devices = append(devices, device)
	}
	sort.Strings(devices)
	for _, device := range devices {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		head := manifest.Devices[device]
		if _, reserved := manifest.Reservations[device]; reserved || !head.Complete || !head.LocationComplete {
			result.Unknown = append(result.Unknown, device)
			result.Complete = false
			continue
		}
		networks, err := flow.NewSet(head.Networks...)
		if err != nil {
			return Result{}, err
		}
		intersection := addresses.Intersection(networks)
		if !intersection.Empty() {
			result.Hits = append(result.Hits, Hit{Device: device, Revision: head.Revision, Addresses: intersection})
		}
	}
	return result, nil
}

// LoadBatch loads each selected immutable revision once, with no database lookup or raw reparse.
func LoadBatch(ctx context.Context, store *snapshot.Store, result Result) (map[string]*fm.Firewall, error) {
	loaded := make(map[string]*fm.Firewall)
	byRevision := make(map[string]*fm.Firewall)
	for _, hit := range result.Hits {
		fw := byRevision[hit.Revision]
		if fw == nil {
			var err error
			fw, err = store.Load(ctx, hit.Revision)
			if err != nil {
				return nil, err
			}
			byRevision[hit.Revision] = fw
		}
		if fw.Metadata().Device != hit.Device {
			return nil, snapshot.ErrFormat
		}
		loaded[hit.Device] = fw
	}
	return loaded, nil
}

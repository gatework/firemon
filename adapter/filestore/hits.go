package filestore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gatework/firemon/hits"
)

const hitsDir = "hits"

// SaveHits stores one collection of a device's rule hit counters; earlier
// collections are kept, so that the observation window can grow.
func (s *Store) SaveHits(ctx context.Context, device string, snap hits.Snapshot) error {
	if err := validName(device); err != nil {
		return err
	}
	dir := filepath.Join(s.root, device, hitsDir)
	if err := s.files.PrepareDirectory(dir); err != nil {
		return fmt.Errorf("filestore: %w", err)
	}
	body, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("filestore: encode hits: %w", err)
	}
	name := snap.Taken.UTC().Format("20060102T150405Z") + ".json"
	if err := s.files.Write(ctx, filepath.Join(dir, name), body); err != nil {
		return fmt.Errorf("filestore: write hits: %w", err)
	}
	return nil
}

// LatestHits returns the most recent hit counters of a device.
func (s *Store) LatestHits(ctx context.Context, device string) (hits.Snapshot, error) {
	if err := validName(device); err != nil {
		return hits.Snapshot{}, err
	}
	dir := filepath.Join(s.root, device, hitsDir)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return hits.Snapshot{}, fmt.Errorf("%w: hits of %s", ErrNotFound, device)
	}
	if err != nil {
		return hits.Snapshot{}, fmt.Errorf("filestore: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return hits.Snapshot{}, fmt.Errorf("%w: hits of %s", ErrNotFound, device)
	}
	slices.Sort(names) // UTC timestamps sort chronologically
	body, err := s.files.Read(ctx, filepath.Join(dir, names[len(names)-1]), maxFile)
	if err != nil {
		return hits.Snapshot{}, fmt.Errorf("filestore: read hits: %w", err)
	}
	var snap hits.Snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		return hits.Snapshot{}, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	return snap, nil
}

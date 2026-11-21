package netconnector

import (
	"context"

	"github.com/gatework/netops/store/disk"
)

// PrivateFiles provides private, atomic storage for snapshots, through
// netops store/disk.
type PrivateFiles struct{}

// PrepareDirectory creates a private directory and its parents.
func (PrivateFiles) PrepareDirectory(path string) error { return disk.PrepareDir(path) }

// Read reads a private regular file up to limit bytes.
func (PrivateFiles) Read(ctx context.Context, path string, limit int64) ([]byte, error) {
	body, _, err := disk.ReadFile(ctx, path, limit)
	return body, err
}

// Write atomically replaces path with body and synchronizes the directory.
func (PrivateFiles) Write(ctx context.Context, path string, body []byte) error {
	_, err := disk.WriteFile(ctx, path, body)
	return err
}

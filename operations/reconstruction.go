package operations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/internal/jsonio"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors"
)

// RevisionLoader must validate immutable snapshot bytes against their revision.
// snapshot.Store implements it; latest heads and source parsing are not involved.
type RevisionLoader interface {
	Load(context.Context, string) (*fm.Firewall, error)
}

// RestorePlan validates material before loading the exact snapshot, then supplies
// production renderer selection to the intent-owned reconstruction algorithm.
func RestorePlan(ctx context.Context, reader io.Reader, expected string, loader RevisionLoader) (*plan.Plan, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if !validChecksum(expected) || dependency.Nil(loader) {
		return nil, "", plan.ErrReconstruction
	}
	if dependency.Nil(reader) {
		return nil, "", ErrInvalid
	}
	material, err := plan.DecodeReconstruction(ctx, reader, expected)
	if err != nil {
		return nil, "", err
	}
	fw, err := loader.Load(ctx, material.Revision())
	if err != nil {
		return nil, "", err
	}
	snapshots := plan.ReconstructionSnapshots{Baseline: fw}
	if revision := material.SourceRevision(); revision != "" {
		snapshots.Source, err = loader.Load(ctx, revision)
		if err != nil {
			return nil, "", err
		}
	}
	p, err := material.Rebuild(ctx, snapshots, vendors.Renderer)
	if err != nil {
		return nil, "", err
	}
	return p, material.Revision(), ctx.Err()
}

func checksum(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func validChecksum(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}
func strictJSON(raw []byte, value any) error {
	err := jsonio.Decode(raw, value)
	if err == jsonio.ErrTrailing {
		return plan.ErrReconstruction
	}
	if err != nil {
		return errors.Join(plan.ErrReconstruction, err)
	}
	return nil
}
func readBounded(ctx context.Context, reader io.Reader, limit int) ([]byte, error) {
	if dependency.Nil(reader) {
		return nil, ErrInvalid
	}
	raw, err := jsonio.Read(ctx, reader, limit)
	if err == jsonio.ErrLimit {
		return nil, plan.ErrReconstruction
	}
	return raw, err
}
func boundedJSON(ctx context.Context, value any, limit int) ([]byte, error) {
	raw, err := jsonio.Encode(ctx, value, limit)
	if err == jsonio.ErrLimit {
		return nil, plan.ErrReconstruction
	}
	return raw, err
}

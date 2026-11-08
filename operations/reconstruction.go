package operations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/internal/dependency"
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
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return errors.Join(plan.ErrReconstruction, err)
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return plan.ErrReconstruction
	}
	return nil
}
func readBounded(ctx context.Context, reader io.Reader, limit int) ([]byte, error) {
	if dependency.Nil(reader) {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, plan.ErrReconstruction
	}
	return raw, ctx.Err()
}

type boundedBuffer struct {
	bytes.Buffer
	limit int
	ctx   context.Context
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > b.limit-b.Len() {
		return 0, plan.ErrReconstruction
	}
	return b.Buffer.Write(p)
}
func boundedJSON(ctx context.Context, value any, limit int) ([]byte, error) {
	b := boundedBuffer{limit: limit, ctx: ctx}
	if err := json.NewEncoder(&b).Encode(value); err != nil {
		return nil, err
	}
	return b.Bytes(), ctx.Err()
}

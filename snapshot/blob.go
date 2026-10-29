package snapshot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	fm "github.com/gatework/firemon"
)

// blob binds encoded immutable evidence to its content-addressed revision.
// It cannot publish a head, release ownership or emit an outbox event.
type blob struct {
	revision string
	data     []byte
}

func encodeBlob(fw *fm.Firewall) (blob, error) {
	var buffer bytes.Buffer
	if err := Encode(&buffer, fw); err != nil {
		return blob{}, err
	}
	sum := sha256.Sum256(buffer.Bytes())
	return blob{revision: hex.EncodeToString(sum[:]), data: buffer.Bytes()}, nil
}

func (s *Store) storeBlob(ctx context.Context, b blob) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path := filepath.Join(s.root, "objects", b.revision+".gob")
	if existing, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(existing, b.data) {
			return ErrFormat
		}
		return ctx.Err()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return atomicWrite(path, b.data)
}

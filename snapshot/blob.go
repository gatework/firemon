package snapshot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	if existing, err := os.Open(path); err == nil {
		return errors.Join(compareBlob(ctx, existing, b.data), existing.Close())
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return atomicWrite(path, b.data)
}

// compareBlob bounds reads by the expected immutable encoding and requires real
// EOF; an oversized or corrupt existing object is never loaded in its entirety.
func compareBlob(ctx context.Context, reader io.Reader, expected []byte) error {
	var buffer [32 << 10]byte
	for len(expected) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := min(len(expected), len(buffer))
		if _, err := io.ReadFull(reader, buffer[:n]); err != nil {
			return fmt.Errorf("%w: compare snapshot blob: %w", ErrFormat, err)
		}
		if !bytes.Equal(buffer[:n], expected[:n]) {
			return ErrFormat
		}
		expected = expected[n:]
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if n, err := io.ReadFull(reader, buffer[:1]); n != 0 || err != io.EOF {
		return errors.Join(ErrFormat, err)
	}
	return ctx.Err()
}

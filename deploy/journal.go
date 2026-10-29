package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sync"
)

const maxJournalBytes = 4 << 20

type FileJournal struct{ root string }
type fileLease struct {
	mu       sync.Mutex
	path, id string
	unlock   func() error
	closed   bool
}

func OpenJournal(root string) (*FileJournal, error) {
	path, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	return &FileJournal{root: path}, nil
}
func (j *FileJournal) Acquire(ctx context.Context, id string) (Lease, error) {
	if id == "" || len(id) > 512 {
		return nil, ErrInvalid
	}
	sum := sha256.Sum256([]byte(id))
	path := filepath.Join(j.root, hex.EncodeToString(sum[:]))
	unlock, err := journalLock(ctx, path+".lock")
	if err != nil {
		return nil, err
	}
	return &fileLease{path: path + ".gob", id: id, unlock: unlock}, nil
}
func (l *fileLease) Load(ctx context.Context) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return Record{}, ErrJournalConflict
	}
	return l.load(ctx)
}
func (l *fileLease) load(ctx context.Context) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	f, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, ErrJournalNotFound
	}
	if err != nil {
		return Record{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxJournalBytes+1))
	if err != nil {
		return Record{}, err
	}
	if len(data) <= sha256.Size || len(data) > maxJournalBytes {
		return Record{}, ErrJournalConflict
	}
	sum := sha256.Sum256(data[sha256.Size:])
	if !bytes.Equal(data[:sha256.Size], sum[:]) {
		return Record{}, ErrJournalConflict
	}
	var envelope struct {
		Version uint16
		Record  Record
	}
	decoder := gob.NewDecoder(bytes.NewReader(data[sha256.Size:]))
	if err := decoder.Decode(&envelope); err != nil {
		return Record{}, fmt.Errorf("journal decode: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Record{}, ErrJournalConflict
	}
	if envelope.Version != 1 || envelope.Record.ID != l.id || envelope.Record.Sequence == 0 {
		return Record{}, ErrJournalConflict
	}
	return envelope.Record, nil
}
func (l *fileLease) Save(ctx context.Context, r Record) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || r.ID != l.id || r.Sequence == math.MaxUint64 || len(r.Receipts) > 20000 {
		return Record{}, ErrJournalConflict
	}
	prior, err := l.load(ctx)
	if errors.Is(err, ErrJournalNotFound) {
		if r.Sequence != 0 {
			return Record{}, ErrJournalConflict
		}
	} else if err != nil {
		return Record{}, err
	} else if prior.Sequence != r.Sequence || prior.Device != r.Device || prior.Vendor != r.Vendor || prior.Context != r.Context || prior.PlanDigest != r.PlanDigest || prior.BaselineRevision != r.BaselineRevision || prior.ConfigurationToken != "" && prior.ConfigurationToken != r.ConfigurationToken || prior.ConfigurationReleased && !r.ConfigurationReleased {
		return Record{}, ErrJournalConflict
	}
	r.Sequence++
	r.Receipts = slices.Clone(r.Receipts)
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(struct {
		Version uint16
		Record  Record
	}{1, r}); err != nil {
		return Record{}, err
	}
	if buf.Len()+sha256.Size > maxJournalBytes {
		return Record{}, ErrJournalConflict
	}
	sum := sha256.Sum256(buf.Bytes())
	data := append(sum[:], buf.Bytes()...)
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if err := writeJournal(l.path, data); err != nil {
		return Record{}, err
	}
	return r, nil
}
func (l *fileLease) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.unlock()
}

func writeJournal(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".journal-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

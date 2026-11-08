package snapshot

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	fm "github.com/gatework/firemon"
)

type measuredReader struct {
	io.Reader
	read, largest int
}

func (r *measuredReader) Read(p []byte) (int, error) {
	r.largest = max(r.largest, len(p))
	n, err := r.Reader.Read(p)
	r.read += n
	return n, err
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

func TestBlobComparisonRequiresRealEOFWithBoundedReads(t *testing.T) {
	expected := bytes.Repeat([]byte("native"), 20000)
	fault := errors.New("disk read failed")
	for _, tc := range []struct {
		name string
		tail io.Reader
		want error
	}{
		{"equal", bytes.NewReader(nil), nil},
		{"extra", bytes.NewReader([]byte("extra")), ErrFormat},
		{"read failure", errorReader{fault}, fault},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &measuredReader{Reader: io.MultiReader(bytes.NewReader(expected), tc.tail)}
			err := compareBlob(t.Context(), reader, expected)
			if !errors.Is(err, tc.want) || reader.read > len(expected)+1 || reader.largest > 32<<10 {
				t.Fatalf("unbounded comparison or lost error: %v read=%d largest=%d", err, reader.read, reader.largest)
			}
			if tc.want != nil && !errors.Is(err, ErrFormat) {
				t.Fatal("bad stored bytes not classified", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	reader := &measuredReader{Reader: bytes.NewReader(expected)}
	if err := compareBlob(ctx, reader, expected); !errors.Is(err, context.Canceled) || reader.read != 0 {
		t.Fatal("cancellation read blob", err)
	}
}

func TestArchiveRejectsOversizedExistingBlobWithoutReplacement(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "test"}, Raw: "native"})
	if err != nil {
		t.Fatal(err)
	}
	revision, err := s.Archive(t.Context(), fw)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.root, "objects", revision+".gob")
	const oversized = DefaultMaxBytes + 1
	if err := os.Truncate(path, oversized); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Archive(t.Context(), fw); !errors.Is(err, ErrFormat) {
		t.Fatal("accepted oversized blob", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() != oversized {
		t.Fatal("replaced stored evidence", err)
	}
}

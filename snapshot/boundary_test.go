package snapshot_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gatework/firemon/snapshot"
)

type shortSnapshotWriter struct{ writes, shortAt int }

func (w *shortSnapshotWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.shortAt {
		return len(p) - 1, nil
	}
	return len(p), nil
}
func TestEncodeRejectsShortWrites(t *testing.T) {
	for _, at := range []int{1, 2} {
		w := &shortSnapshotWriter{shortAt: at}
		err := snapshot.Encode(w, graph(t, "fw", "", true))
		if !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("write %d: %v", at, err)
		}
		if w.writes != at {
			t.Fatal("continued after short write")
		}
	}
}
func TestDecodePreservesTruncatedIOCause(t *testing.T) {
	var data bytes.Buffer
	if err := snapshot.Encode(&data, graph(t, "fw", "", true)); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{1, 52, 53} {
		_, err := snapshot.Decode(bytes.NewReader(data.Bytes()[:n]), snapshot.DefaultMaxBytes)
		want := io.ErrUnexpectedEOF
		if n == 52 {
			want = io.EOF
		}
		if !errors.Is(err, snapshot.ErrFormat) || !errors.Is(err, want) {
			t.Fatalf("length %d lost cause: %v", n, err)
		}
	}
}
func TestPublicationCancellationPrecedesValidation(t *testing.T) {
	s, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Publish(ctx, nil, snapshot.PublishOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("publish: %v", err)
	}
	if err := s.Reserve(ctx, "", "", ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("reserve: %v", err)
	}
	if err := s.Acknowledge(ctx, "", 2, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("acknowledge: %v", err)
	}
}

func TestStoreRejectsEmptyRootWithoutCreatingFiles(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if _, err := snapshot.Open(""); err == nil {
		t.Error("empty root accepted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("invalid root created files")
	}
}
func TestCodecRejectsNilStreamsWithoutPanicking(t *testing.T) {
	fw := graph(t, "fw", "", true)
	var buffer *bytes.Buffer
	cases := map[string]func() error{
		"nil writer":       func() error { return snapshot.Encode(nil, fw) },
		"typed nil writer": func() error { return snapshot.Encode(buffer, fw) },
		"nil reader":       func() error { _, err := snapshot.Decode(nil, 100); return err },
		"typed nil reader": func() error { _, err := snapshot.Decode(buffer, 100); return err },
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if v := recover(); v != nil {
					t.Fatalf("invalid stream panicked: %v", v)
				}
			}()
			if err := call(); err == nil {
				t.Fatal("nil stream accepted")
			}
		})
	}
}

func TestStoreInvalidInputsHaveNoFilesystemEffects(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := snapshot.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"load":        func() error { _, err := s.Load(ctx, "../bad"); return err },
		"current":     func() error { _, _, err := s.Current(ctx, ""); return err },
		"publish":     func() error { _, err := s.Publish(ctx, nil, snapshot.PublishOptions{}); return err },
		"reserve":     func() error { return s.Reserve(ctx, "fw", "bad", "token") },
		"release":     func() error { return s.ReleaseUnchanged(ctx, "fw", "token", "bad") },
		"acknowledge": func() error { return s.Acknowledge(ctx, "sink", 2, 1) },
		"archive":     func() error { _, err := s.Archive(ctx, nil); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, snapshot.ErrInvalid) {
				t.Fatal(err)
			}
		})
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "objects" {
		t.Fatalf("invalid input changed store: %v", entries)
	}
	for _, store := range []*snapshot.Store{nil, {}} {
		if _, err := store.Manifest(ctx); !errors.Is(err, snapshot.ErrInvalid) {
			t.Fatal(err)
		}
		if _, err := store.Load(ctx, "bad"); !errors.Is(err, snapshot.ErrInvalid) {
			t.Fatal(err)
		}
		if _, _, err := store.Current(ctx, "fw"); !errors.Is(err, snapshot.ErrInvalid) {
			t.Fatal(err)
		}
		if _, err := store.Publish(ctx, nil, snapshot.PublishOptions{}); !errors.Is(err, snapshot.ErrInvalid) {
			t.Fatal(err)
		}
		if _, err := store.Archive(ctx, nil); !errors.Is(err, snapshot.ErrInvalid) {
			t.Fatal(err)
		}
		if err := store.Reserve(ctx, "fw", "bad", "token"); !errors.Is(err, snapshot.ErrInvalid) {
			t.Fatal(err)
		}
		if err := store.ReleaseUnchanged(ctx, "fw", "token", "bad"); !errors.Is(err, snapshot.ErrInvalid) {
			t.Fatal(err)
		}
		if err := store.Acknowledge(ctx, "sink", 0, 0); !errors.Is(err, snapshot.ErrInvalid) {
			t.Fatal(err)
		}
	}
}
func TestArchiveAndPublishShareExactBlobIdentity(t *testing.T) {
	ctx := context.Background()
	s, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fw := graph(t, "fw", "native", true)
	revision, err := s.Archive(ctx, fw)
	if err != nil {
		t.Fatal(err)
	}
	published, err := s.Publish(ctx, fw, snapshot.PublishOptions{PublicationID: "first"})
	if err != nil {
		t.Fatal(err)
	}
	if published.Revision != revision {
		t.Fatal("archive and publication differ")
	}
	loaded, err := s.Load(ctx, revision)
	if err != nil || loaded.SemanticDigest() != fw.SemanticDigest() {
		t.Fatal(err)
	}
}

func TestCurrentClassifiesCorruptHeadAsStoredEvidence(t *testing.T) {
	for _, field := range []string{"revision", "digest"} {
		t.Run(field, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			s, err := snapshot.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Publish(ctx, graph(t, "fw", "native", true), snapshot.PublishOptions{PublicationID: "first"}); err != nil {
				t.Fatal(err)
			}
			m, err := s.Manifest(ctx)
			if err != nil {
				t.Fatal(err)
			}
			head := m.Devices["fw"]
			if field == "revision" {
				head.Revision = "corrupt"
			} else {
				head.SemanticDigest = "corrupt"
			}
			m.Devices["fw"] = head
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.Current(ctx, "fw"); !errors.Is(err, snapshot.ErrFormat) || errors.Is(err, snapshot.ErrInvalid) {
				t.Fatalf("stored head confused with invalid call: %v", err)
			}
		})
	}
}

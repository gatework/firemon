package snapshot

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
)

func TestManifestLimitRejectsPublicationWithoutReplacingCommittedState(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "test"}, Raw: "native"})
	if err != nil {
		t.Fatal(err)
	}
	base, err := s.Publish(t.Context(), fw, PublishOptions{PublicationID: "base"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reserve(t.Context(), "fw", base.Revision, "operation"); err != nil {
		t.Fatal(err)
	}
	before, err := s.Manifest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.root, "manifest.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s.manifestLimit = int64(len(raw))
	_, err = s.Publish(t.Context(), fw, PublishOptions{Expected: base.Revision, PublicationID: strings.Repeat("p", len(raw)), Reservation: "operation", Live: true})
	if !errors.Is(err, ErrLimit) || errors.Is(err, ErrFormat) {
		t.Fatalf("publication limit classification: %v", err)
	}
	afterRaw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, afterRaw) {
		t.Fatalf("replaced committed manifest: %v", err)
	}
	after, err := s.Manifest(t.Context())
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("changed head, reservation or outbox: %v", err)
	}
	if _, _, err := s.Current(t.Context(), "fw"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("lost reservation: %v", err)
	}
	again, err := s.Publish(t.Context(), fw, PublishOptions{PublicationID: "base"})
	if err != nil || again != base {
		t.Fatalf("existing publication no longer idempotent: %+v %v", again, err)
	}
}

func TestManifestLimitReadsExactBoundaryAndRejectsHiddenTrailingBytes(t *testing.T) {
	const raw = `{"Version":1,"Generation":0,"Devices":{},"Reservations":{},"Publications":{},"Events":null,"Acknowledged":{}}`
	for _, tc := range []struct {
		name, suffix string
		large        bool
	}{
		{"exact", "", false}, {"whitespace beyond limit", " ", true}, {"value beyond limit", "{}", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			s.manifestLimit = int64(len(raw))
			if err := os.WriteFile(filepath.Join(s.root, "manifest.json"), []byte(raw+tc.suffix), 0600); err != nil {
				t.Fatal(err)
			}
			_, err = s.Manifest(t.Context())
			if tc.large {
				if !errors.Is(err, ErrLimit) || !errors.Is(err, ErrFormat) {
					t.Fatalf("stored limit classification: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

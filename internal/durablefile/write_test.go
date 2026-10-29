package durablefile

import (
	"errors"
	"io"
	"reflect"
	"testing"
)

type fakeFile struct {
	events   *[]string
	fail     string
	sentinel error
}

func (f fakeFile) event(s string) error {
	*f.events = append(*f.events, s)
	if f.fail == s {
		return f.sentinel
	}
	return nil
}
func (f fakeFile) Name() string                { return "temp" }
func (f fakeFile) Write(b []byte) (int, error) { return len(b), f.event("write") }
func (f fakeFile) Sync() error                 { return f.event("sync") }
func (f fakeFile) Close() error                { return f.event("close") }

type fakeDirectory struct{ fakeFile }

func (f fakeDirectory) Sync() error  { return f.event("directory-sync") }
func (f fakeDirectory) Close() error { return f.event("directory-close") }
func TestReplacementFailureBoundaries(t *testing.T) {
	sequence := []string{"create", "write", "sync", "close", "rename", "open", "directory-sync", "directory-close"}
	for _, fail := range append([]string{""}, sequence...) {
		t.Run(fail, func(t *testing.T) {
			var events []string
			sentinel := errors.New("injected")
			f := fakeFile{&events, fail, sentinel}
			fs := filesystem{create: func(string, string) (file, error) { err := f.event("create"); return f, err }, rename: func(string, string) error { return f.event("rename") }, remove: func(string) error { return nil }, open: func(string) (directory, error) { err := f.event("open"); return fakeDirectory{f}, err }}
			err := replace("target", []byte("data"), fs)
			if fail == "" {
				if err != nil || !reflect.DeepEqual(events, sequence) {
					t.Fatalf("%v %v", events, err)
				}
				return
			}
			if !errors.Is(err, sentinel) {
				t.Fatalf("lost %s failure: %v", fail, err)
			}
			// No replacement may occur after any failure before rename.
			if fail == "write" || fail == "sync" || fail == "close" {
				for _, e := range events {
					if e == "rename" {
						t.Fatal("replacement after failed durability step")
					}
				}
			}
		})
	}
}

type failingWriteFile struct {
	fakeFile
	short                       bool
	writeErr, syncErr, closeErr error
}

func (f failingWriteFile) Write(b []byte) (int, error) {
	if f.short {
		return len(b) - 1, f.writeErr
	}
	return len(b), f.writeErr
}
func (f failingWriteFile) Sync() error  { return f.syncErr }
func (f failingWriteFile) Close() error { return f.closeErr }
func TestShortWriteAndJoinedCloseFailures(t *testing.T) {
	primary, closing := errors.New("primary"), errors.New("close")
	for _, tc := range []struct {
		name                    string
		short                   bool
		writeErr, syncErr, want error
	}{
		{name: "short-write", short: true, want: io.ErrShortWrite},
		{name: "write-and-close", writeErr: primary, want: primary},
		{name: "sync-and-close", syncErr: primary, want: primary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events []string
			f := failingWriteFile{fakeFile: fakeFile{events: &events}, short: tc.short, writeErr: tc.writeErr, syncErr: tc.syncErr, closeErr: closing}
			fs := filesystem{create: func(string, string) (file, error) { return f, nil }, remove: func(string) error { return nil }, rename: func(string, string) error { t.Fatal("renamed failed write"); return nil }, open: func(string) (directory, error) { t.Fatal("opened directory after failed write"); return nil, nil }}
			err := replace("target", []byte("data"), fs)
			if !errors.Is(err, tc.want) || !errors.Is(err, closing) {
				t.Fatalf("lost primary/close errors: %v", err)
			}
		})
	}
}

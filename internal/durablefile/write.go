// Package durablefile provides durable replacement writes and advisory locks.
package durablefile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

type file interface {
	Name() string
	Write([]byte) (int, error)
	Sync() error
	Close() error
}
type directory interface {
	Sync() error
	Close() error
}
type filesystem struct {
	create func(string, string) (file, error)
	rename func(string, string) error
	remove func(string) error
	open   func(string) (directory, error)
}

func Replace(path string, data []byte) error {
	return replace(path, data, filesystem{create: func(d, p string) (file, error) { return os.CreateTemp(d, p) }, rename: os.Rename, remove: os.Remove, open: func(p string) (directory, error) { return os.Open(p) }})
}
func replace(path string, data []byte, fs filesystem) error {
	dir := filepath.Dir(path)
	f, err := fs.create(dir, ".pending-")
	if err != nil {
		return err
	}
	defer fs.remove(f.Name())
	if n, err := f.Write(data); err != nil || n != len(data) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return errors.Join(err, f.Close())
	}
	if err := f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := fs.rename(f.Name(), path); err != nil {
		return err
	}
	d, err := fs.open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

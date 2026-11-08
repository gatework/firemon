//go:build darwin || linux || freebsd || openbsd || netbsd

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

// inputFile is owned by one command read. Its context lasts only until finish.
// Nonblocking open avoids waiting forever for a FIFO writer. An empty pipe is
// rejected: producers must connect before the command reads, including stdin.
type inputFile struct {
	file           *os.File
	ctx            context.Context
	pipe, received bool
}

func openInput(ctx context.Context, path string) (*inputFile, func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	closeFile := sync.OnceValue(func() error {
		err := f.Close()
		if err != nil {
			return fmt.Errorf("close input: %w", err)
		}
		return nil
	})
	info, err := f.Stat()
	if err != nil {
		return nil, nil, errors.Join(err, closeFile(), ctx.Err())
	}
	// Darwin's /dev/fd paths duplicate the existing descriptor and can ignore
	// open flags. Enforce nonblocking mode before a read or cancellation close.
	raw, err := f.SyscallConn()
	if err == nil {
		var flagsErr error
		err = raw.Control(func(fd uintptr) { flagsErr = syscall.SetNonblock(int(fd), true) })
		err = errors.Join(err, flagsErr)
	}
	if err != nil {
		return nil, nil, errors.Join(&os.PathError{Op: "nonblock", Path: path, Err: err}, closeFile(), ctx.Err())
	}
	stop := context.AfterFunc(ctx, func() { closeFile() })
	finish := func() error {
		stop()
		// OnceValue also waits for a cancellation callback already closing f.
		return errors.Join(closeFile(), ctx.Err())
	}
	return &inputFile{file: f, ctx: ctx, pipe: info.Mode()&os.ModeNamedPipe != 0}, finish, nil
}

func (f *inputFile) Read(p []byte) (int, error) {
	for {
		if err := f.ctx.Err(); err != nil {
			return 0, err
		}
		n, err := f.file.Read(p)
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			// Darwin intentionally excludes opened FIFOs from its kqueue poller.
			// Wait without a worker goroutine, then retry the nonblocking read.
			timer := time.NewTimer(10 * time.Millisecond)
			select {
			case <-f.ctx.Done():
				timer.Stop()
				return 0, f.ctx.Err()
			case <-timer.C:
			}
			continue
		}
		if n > 0 {
			f.received = true
		}
		if canceled := f.ctx.Err(); canceled != nil {
			return n, errors.Join(err, canceled)
		}
		if f.pipe && !f.received && n == 0 && err == io.EOF {
			return 0, usage(errors.New("empty input pipe; connect a producer before reading"))
		}
		return n, err
	}
}

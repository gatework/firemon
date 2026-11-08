//go:build darwin || linux || freebsd || openbsd || netbsd

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCLISignalsInterruptOpenInputPipe(t *testing.T) {
	root := t.TempDir()
	binary := buildCLI(t)
	for _, tc := range []struct {
		name   string
		args   []string
		signal os.Signal
		code   int
	}{
		{"request interrupt", []string{"request-plan", "--store", root, "--file", "/dev/stdin"}, os.Interrupt, 130},
		{"request terminate", []string{"request-plan", "--store", root, "--file", "/dev/stdin"}, syscall.SIGTERM, 143},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, tc.args...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			// Exceed a pipe buffer, while staying below all command input limits.
			// Completing this write proves the real command has started reading,
			// after mainExit installed the signal handler. No timing sleeps needed.
			data := bytes.Repeat([]byte(strings.Repeat(" ", 31)+"\n"), 1<<16)
			if _, err := input.Write(data); err != nil {
				t.Fatalf("command did not consume stdin: %v", err)
			}
			if err := cmd.Process.Signal(tc.signal); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			exit, ok := errors.AsType[*exec.ExitError](err)
			if !ok || exit.ExitCode() != tc.code || stdout.Len() != 0 || !strings.Contains(stderr.String(), "context canceled") {
				t.Fatalf("signal did not stop input: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
			}
		})
	}
}

func TestCLIRejectsFIFOWithoutProducer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unconnected.fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, buildCLI(t), "request-plan", "--store", t.TempDir(), "--file", path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	exit, ok := errors.AsType[*exec.ExitError](err)
	if !ok || exit.ExitCode() != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "empty input pipe") {
		t.Fatalf("unconnected FIFO: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
}

func TestConnectedFIFOReadsThroughRealEOF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connected.fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	producer, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	input, finish, err := openInput(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	const raw = `{"version":1}`
	if _, err := producer.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	if err := producer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(input)
	if err != nil || string(data) != raw {
		t.Fatalf("FIFO content: %q %v", data, err)
	}
	if err := finish(); err != nil {
		t.Fatal(err)
	}
}

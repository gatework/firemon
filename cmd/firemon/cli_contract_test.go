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
)

func TestCommandHelpIsSuccessfulAndVisible(t *testing.T) {
	commands := []string{"", "import", "inspect", "query", "nat", "plan", "request-query", "request-plan", "inspect-address", "risk-report", "convergence-report", "compare-revisions", "usage-report", "reclamation-report", "reclamation-plan", "migration-report", "migration-plan", "convergence-plan"}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			args := []string{"--help"}
			if command != "" {
				args = append([]string{command}, args...)
			}
			var out bytes.Buffer
			if err := execute(t.Context(), args, &out); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "Usage: firemon") {
				t.Fatalf("missing help: %q", out.String())
			}
			if command == "" {
				for _, name := range commands[1:] {
					if !strings.Contains(out.String(), name) {
						t.Errorf("root help omits %s", name)
					}
				}
			}
		})
	}
}

type shortOutput struct{}

func (shortOutput) Write(p []byte) (int, error) { return len(p) / 2, nil }

func TestJSONOutputRejectsShortWrites(t *testing.T) {
	for name, encode := range map[string]func(io.Writer, any) error{"json": output, "report": analysisOutput} {
		t.Run(name, func(t *testing.T) {
			if err := encode(shortOutput{}, struct{ Complete bool }{true}); !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("short output: %v", err)
			}
		})
	}
}

type failedOutput struct{ err error }

func (w failedOutput) Write([]byte) (int, error) { return 0, w.err }

func TestCLIReportsOutputAndCancellationErrors(t *testing.T) {
	failure := errors.New("output unavailable")
	for _, args := range [][]string{{"--help"}, {"request-plan", "-h"}} {
		if err := execute(t.Context(), args, failedOutput{failure}); !errors.Is(err, failure) {
			t.Fatalf("%v: lost output error: %v", args, err)
		}
		var stderr bytes.Buffer
		if code := runCLI(t.Context(), args, failedOutput{failure}, &stderr); code != 1 || !strings.Contains(stderr.String(), failure.Error()) {
			t.Fatalf("%v: code=%d stderr=%q", args, code, stderr.String())
		}
	}
	for _, tt := range []struct {
		cause error
		code  int
	}{{context.Canceled, 130}, {&signalCancellation{os.Interrupt}, 130}, {&signalCancellation{syscall.SIGTERM}, 143}} {
		ctx, cancel := context.WithCancelCause(t.Context())
		cancel(tt.cause)
		var stdout, stderr bytes.Buffer
		if code := runCLI(ctx, []string{"inspect"}, &stdout, &stderr); code != tt.code || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", tt.cause, code, stdout.String(), stderr.String())
		}
	}
}

func buildCLI(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "firemon")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, out)
	}
	return binary
}

func TestCLIProcessExitCodes(t *testing.T) {
	dir := t.TempDir()
	binary := buildCLI(t)
	badJSON := filepath.Join(dir, "request.json")
	if err := os.WriteFile(badJSON, []byte(`{"version":1,"unexpected":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		args []string
		code int
	}{
		{"root help", []string{"--help"}, 0},
		{"command help", []string{"request-plan", "--help"}, 0},
		{"missing command", nil, 2},
		{"unknown command", []string{"unknown"}, 2},
		{"invalid flag", []string{"inspect", "--unknown"}, 2},
		{"missing argument", []string{"inspect"}, 2},
		{"trailing argument", []string{"request-plan", "extra"}, 2},
		{"invalid document", []string{"request-plan", "--store", dir, "--file", badJSON}, 2},
		{"missing document", []string{"request-plan", "--store", dir, "--file", filepath.Join(dir, "absent.json")}, 1},
		{"missing snapshot", []string{"inspect", "--store", dir, "--device", "absent"}, 1},
		{"request read failure", []string{"request-plan", "--store", dir, "--file", dir}, 1},
		{"invalid revision", []string{"inspect", "--store", dir, "--revision", "bad"}, 2},
		{"missing vendor", []string{"import", "--store", dir, "--device", "fw", "--file", badJSON, "--publication", "one"}, 2},
		{"unsupported vendor", []string{"import", "--store", dir, "--device", "fw", "--vendor", "unsupported", "--file", badJSON, "--publication", "one"}, 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), binary, tt.args...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			code := 0
			if exit, ok := errors.AsType[*exec.ExitError](err); ok {
				code = exit.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != tt.code || code == 0 && (stdout.Len() == 0 || stderr.Len() != 0) || code != 0 && (stdout.Len() != 0 || stderr.Len() == 0) {
				t.Fatalf("code=%d want=%d stdout=%q stderr=%q", code, tt.code, stdout.String(), stderr.String())
			}
		})
	}
}

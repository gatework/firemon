package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
)

type command struct {
	name, summary string
	run           func(context.Context, string, []string, io.Writer) error
}

var commands = []command{
	{"parse", "Check native configurations without publishing snapshots", func(ctx context.Context, _ string, args []string, out io.Writer) error {
		return parseConfig(ctx, args, out)
	}},
	{"import", "Parse and publish a native configuration", func(ctx context.Context, _ string, args []string, out io.Writer) error {
		return importConfig(ctx, args, out)
	}},
	{"inspect", "Inspect a stored firewall snapshot", inspectOrQuery},
	{"query", "Evaluate policy coverage", inspectOrQuery},
	{"nat", "Evaluate native address translation", inspectOrQuery},
	{"plan", "Plan a proven policy change", inspectOrQuery},
	{"request-query", "Evaluate a batch of business requests", requestCommand},
	{"request-plan", "Plan a batch of business requests", requestCommand},
	{"inspect-address", "Inspect address usage", analysisCommand},
	{"risk-report", "Evaluate risk definitions", analysisCommand},
	{"convergence-report", "Discover policy convergence candidates", analysisCommand},
	{"compare-revisions", "Compare immutable revisions", analysisCommand},
	{"usage-report", "Read native usage evidence", lifecycleCommand},
	{"reclamation-report", "Evaluate reclamation evidence", lifecycleCommand},
	{"reclamation-plan", "Plan proven reclamation", lifecycleCommand},
	{"migration-report", "Evaluate policy migration", lifecycleCommand},
	{"migration-plan", "Plan policy migration", lifecycleCommand},
	{"convergence-plan", "Plan proven policy convergence", lifecycleCommand},
}

// CLI ceilings are independent of engine defaults: changing a library default
// must not silently raise the work accepted by an existing command.
var cliLimits = policy.Limits{MaxVisits: 100_000, MaxRegions: 4096, MaxCombinations: 4096}

type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }
func usage(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if _, ok := errors.AsType[*os.PathError](err); ok {
		return err
	}
	return &usageError{err: err}
}

// Snapshot invalid-input errors at CLI store calls describe user arguments;
// corruption, conflicts and missing stored revisions remain runtime failures.
func snapshotArgumentError(err error) error {
	if errors.Is(err, snapshot.ErrInvalid) {
		return usage(err)
	}
	return err
}

func execute(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return usage(errors.New("a command is required; use firemon --help"))
	}
	if args[0] == "--help" || args[0] == "-h" {
		if len(args) != 1 {
			return usage(errors.New("unexpected arguments after help"))
		}
		var help bytes.Buffer
		help.WriteString("Usage: firemon <command> [flags]\n\nCommands:\n")
		for _, c := range commands {
			fmt.Fprintf(&help, "  %-20s %s\n", c.name, c.summary)
		}
		help.WriteString("\nUse firemon <command> --help for command flags.\n")
		help.WriteString("Input pipes must have a connected producer; an empty FIFO is rejected.\n")
		return writeOutput(out, help.Bytes())
	}
	for _, c := range commands {
		if c.name != args[0] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		err := c.run(ctx, c.name, args[1:], out)
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	return usage(fmt.Errorf("unknown command %q; use firemon --help", args[0]))
}

type commandFlags struct {
	*flag.FlagSet
	help bytes.Buffer
	out  io.Writer
}

func flags(name string, out io.Writer) *commandFlags {
	f := &commandFlags{FlagSet: flag.NewFlagSet(name, flag.ContinueOnError), out: out}
	f.SetOutput(&f.help)
	f.Usage = func() {
		fmt.Fprintf(&f.help, "Usage: firemon %s [flags]\n\n", name)
		f.PrintDefaults()
	}
	return f
}

func (f *commandFlags) Parse(args []string) error {
	err := f.FlagSet.Parse(args)
	if err == flag.ErrHelp {
		if err := writeOutput(f.out, f.help.Bytes()); err != nil {
			return err
		}
		return flag.ErrHelp
	}
	return usage(err)
}

// checkedOutput also protects json.Encoder, which relies on Writer's contract
// that a short write always carries an error.
type checkedOutput struct{ io.Writer }

func (w checkedOutput) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

func writeOutput(out io.Writer, data []byte) error {
	_, err := (checkedOutput{out}).Write(data)
	if err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func runCLI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	err := execute(ctx, args, stdout)
	if err == nil {
		return 0
	}
	if _, writeErr := fmt.Fprintln(checkedOutput{stderr}, "firemon:", err); writeErr != nil {
		return 1
	}
	if errors.Is(err, context.Canceled) {
		if cause, ok := errors.AsType[*signalCancellation](context.Cause(ctx)); ok && cause.signal == syscall.SIGTERM {
			return 143
		}
		return 130
	}
	if _, ok := errors.AsType[*os.PathError](err); ok {
		return 1
	}
	if _, ok := errors.AsType[*usageError](err); ok {
		return 2
	}
	return 1
}

type signalCancellation struct{ signal os.Signal }

func (e *signalCancellation) Error() string     { return e.signal.String() + " signal received" }
func (e *signalCancellation) Is(err error) bool { return err == context.Canceled }

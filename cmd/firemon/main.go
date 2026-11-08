package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	os.Exit(mainExit(os.Args[1:], os.Stdout, os.Stderr))
}

func mainExit(args []string, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithCancelCause(context.Background())
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	done := make(chan struct{})
	defer func() { cancel(nil); <-done }()
	go func() {
		defer close(done)
		select {
		case s := <-signals:
			cancel(&signalCancellation{signal: s})
		case <-ctx.Done():
		}
	}()
	return runCLI(ctx, args, stdout, stderr)
}

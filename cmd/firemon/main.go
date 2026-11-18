// Command firemon queries, designs and deploys firewall policy for
// Hillstone and PAN-OS devices.
package main

import (
	"context"
	"os"
	"os/signal"
	"time"

	"github.com/gatework/firemon/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Run(ctx, os.Args[1:], cli.Deps{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv, Now: time.Now})
	stop()
	os.Exit(code)
}

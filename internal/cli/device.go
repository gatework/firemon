package cli

import (
	"errors"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/net-connector/connector"

	"github.com/gatework/firemon/adapter/netconnector"
	"github.com/gatework/firemon/internal/bootstrap"
)

// Environment variables holding credentials; credentials are never flags.
const (
	envPassword = "FIREMON_PASSWORD"
	envEnable   = "FIREMON_ENABLE_PASSWORD"
)

// deviceFlags select the device to read or change.
type deviceFlags struct {
	host       string
	user       string
	port       int
	knownHosts string
	timeout    time.Duration
}

func (d *deviceFlags) register(cmd *cobra.Command) {
	f := cmd.PersistentFlags()
	f.StringVar(&d.host, "host", "", "device address")
	f.StringVar(&d.user, "user", "", "login user; the password is read from "+envPassword)
	f.IntVar(&d.port, "port", 22, "SSH port")
	f.StringVar(&d.knownHosts, "known-hosts", "", "SSH known_hosts file (default: the user's)")
	f.DurationVar(&d.timeout, "command-timeout", 2*time.Minute, "timeout of one device command")
}

func (d *deviceFlags) client(p bootstrap.Platform, getenv func(string) string) (*netconnector.Client, error) {
	if d.host == "" || d.user == "" {
		return nil, &usageError{errors.New("set --config, or --host and --user to read the device")}
	}
	return bootstrap.Client(p, connector.ConnectionConfig{
		Host: d.host, Username: d.user, Password: getenv(envPassword), EnablePassword: getenv(envEnable),
		Protocol: connector.ProtocolSSH, Port: d.port, KnownHosts: d.knownHosts, CommandTimeout: d.timeout,
	})
}

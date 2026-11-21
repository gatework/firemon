package netconnector

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/gatework/net-connector/connector"
	"github.com/gatework/net-connector/driver"
	"github.com/gatework/net-connector/transport"
	"github.com/gatework/net-connector/transport/ssh"
	"github.com/gatework/net-connector/vendors"
	"github.com/gatework/netops/apply"
	"github.com/gatework/netops/change"
	"github.com/gatework/netops/credential"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/failure"
	"github.com/gatework/netops/secret"

	"github.com/gatework/firemon"
)

// ErrUnsupportedVendor reports a vendor without a net-connector platform.
var ErrUnsupportedVendor = errors.New("netconnector: unsupported vendor")

// CommitCommand ends a PAN-OS deployment: the set commands before it are
// collected and committed as one candidate batch.
const CommitCommand = "commit"

// ParseFunc converts running-configuration text.
type ParseFunc func(text string) (*firemon.Config, error)

// Client talks to one device.
type Client struct {
	d      *connector.Dialer
	dev    device.Device
	vendor firemon.Vendor
	parse  ParseFunc
}

// SSHConfig contains the SSH settings accepted by the operator interface.
type SSHConfig struct {
	Host, Username, Password, EnablePassword string
	Port                                     int
	KnownHosts                               string
	CommandTimeout                           time.Duration
}

// NewSSH returns a client using SSH and the supplied device credentials.
// Host keys are checked strictly against KnownHosts (default
// ~/.ssh/known_hosts).
func NewSSH(vendor firemon.Vendor, s SSHConfig, parse ParseFunc) (*Client, error) {
	sd, err := ssh.New(ssh.Options{KnownHosts: s.KnownHosts})
	if err != nil {
		return nil, fmt.Errorf("netconnector: %w", err)
	}
	creds := credential.Static{Username: s.Username, Password: secret.New(s.Password), EnablePassword: secret.New(s.EnablePassword)}
	return New(vendor, s.Host, sd, creds, s.Port, s.CommandTimeout, parse)
}

// New returns a client for the device at host, reached through t. parse
// converts the running configuration of vendor.
func New(vendor firemon.Vendor, host string, t transport.Dialer, creds credential.Provider, port int, timeout time.Duration, parse ParseFunc) (*Client, error) {
	platform, err := platformOf(vendor)
	if err != nil {
		return nil, err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("netconnector: device address %q: %w", host, err)
	}
	d, err := connector.NewDialer(connector.Options{Registry: vendors.Builtin(), Credentials: creds, Transport: t, Port: port, Timeout: timeout})
	if err != nil {
		return nil, fmt.Errorf("netconnector: %w", err)
	}
	dev := device.Device{ID: addr.String(), Mgmt: addr, Platform: platform}.Normalize()
	return &Client{d: d, dev: dev, vendor: vendor, parse: parse}, nil
}

func platformOf(v firemon.Vendor) (string, error) {
	switch v {
	case firemon.VendorHillstone:
		return "hillstone", nil
	case firemon.VendorPaloAlto:
		return "palo_alto", nil
	case firemon.VendorUnset:
		return "", ErrUnsupportedVendor
	default:
		return "", ErrUnsupportedVendor
	}
}

// Device returns the identity of the target.
func (c *Client) Device() device.Device { return c.dev.Clone() }

// Show runs one read-only command and returns its output. It is meant for
// display commands such as rule hit counters; it never enters
// configuration mode.
func (c *Client) Show(ctx context.Context, command string) (string, error) {
	var out string
	err := c.with(ctx, func(ctx context.Context, s *connector.Session) error {
		var err error
		out, err = s.Show(ctx, command)
		return err
	})
	return out, err
}

// RunningConfig returns the device's running configuration text. On PAN-OS
// the software version from "show system info" is put at its head.
func (c *Client) RunningConfig(ctx context.Context) (string, error) {
	var text string
	err := c.with(ctx, func(ctx context.Context, s *connector.Session) error {
		var err error
		if text, err = s.Config(ctx); err != nil {
			return err
		}
		if c.vendor == firemon.VendorPaloAlto {
			// Best effort: without it the version is unknown.
			if info, err := s.Show(ctx, "show system info"); err == nil {
				text = WithVersion(text, info)
			}
		}
		return nil
	})
	return text, err
}

// WithVersion puts the sw-version line of "show system info" output at
// the head of a PAN-OS set configuration, where the parser reads it; text
// is unchanged when info has none.
func WithVersion(text, info string) string {
	for line := range strings.SplitSeq(info, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "sw-version:"); ok && strings.TrimSpace(v) != "" {
			return "sw-version: " + strings.TrimSpace(v) + "\n" + text
		}
	}
	return text
}

// Open lends one session for a deployment and reports the operation and
// close errors separately, as apply.Settle needs.
func (c *Client) Open(ctx context.Context, run func(context.Context, apply.Session[*firemon.Config]) error) (opErr, closeErr error) {
	return c.d.Open(ctx, c.dev, func(ctx context.Context, s *connector.Session) error {
		return run(ctx, &session{s: s, vendor: c.vendor, parse: c.parse})
	})
}

// Save persists the running configuration where the platform separates
// saving from changing (Hillstone). It is a no-op for commit platforms.
func (c *Client) Save(ctx context.Context) error {
	if c.vendor == firemon.VendorPaloAlto {
		return nil
	}
	return c.with(ctx, func(ctx context.Context, s *connector.Session) error { return s.Save(ctx) })
}

func (c *Client) with(ctx context.Context, run func(context.Context, *connector.Session) error) error {
	opErr, closeErr := c.d.Open(ctx, c.dev, run)
	return errors.Join(opErr, closeErr)
}

// session adapts one connector session to apply.Session.
type session struct {
	s       *connector.Session
	vendor  firemon.Vendor
	parse   ParseFunc
	pending []string // PAN-OS set commands awaiting the commit
}

// Read reads and parses the running configuration.
func (s *session) Read(ctx context.Context) (*firemon.Config, error) {
	text, err := s.s.Config(ctx)
	if err != nil {
		return nil, err
	}
	return s.parse(text)
}

// Write sends one deployment write. Hillstone lines go to the device one at
// a time. PAN-OS set commands are collected and sent with CommitCommand as
// one candidate batch whose commit the device must confirm.
func (s *session) Write(ctx context.Context, cmd change.Command) error {
	if s.vendor != firemon.VendorPaloAlto {
		return s.s.Write(ctx, cmd)
	}
	if cmd.Text != CommitCommand {
		s.pending = append(s.pending, cmd.Text)
		return nil
	}
	if len(s.pending) == 0 {
		return failure.New(failure.CodeInvalid, "netconnector: empty commit")
	}
	body := s.pending
	s.pending = nil
	_, err := s.s.Commit(ctx, body, driver.CommitOptions{})
	return err
}

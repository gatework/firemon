package netconnector

import (
	"context"
	"errors"
	"fmt"

	"github.com/gatework/go-netops/apply"
	"github.com/gatework/net-connector/connector"
	nchillstone "github.com/gatework/net-connector/vendors/hillstone"
	ncpaloalto "github.com/gatework/net-connector/vendors/paloalto"

	"github.com/gatework/firemon"
)

// ErrUnsupportedVendor reports a vendor without a connector platform.
var ErrUnsupportedVendor = errors.New("netconnector: unsupported vendor")

// ParseFunc converts running-configuration text.
type ParseFunc func(text string) (*firemon.Config, error)

// Client talks to one device.
type Client struct {
	vendor firemon.Vendor
	conn   connector.ConnectionConfig
	parse  ParseFunc
}

// New returns a client for one device. parse converts the running
// configuration of vendor.
func New(vendor firemon.Vendor, conn connector.ConnectionConfig, parse ParseFunc) (*Client, error) {
	if _, err := driverFor(vendor); err != nil {
		return nil, err
	}
	return &Client{vendor: vendor, conn: conn, parse: parse}, nil
}

// RunningConfig returns the device's running configuration text.
func (c *Client) RunningConfig(ctx context.Context) (string, error) {
	var text string
	err := c.with(ctx, func(ctx context.Context, op *connector.Operation) error {
		var err error
		text, err = runningConfig(ctx, op)
		return err
	})
	return text, err
}

// Open implements deploy.Opener: it lends one session for the whole run.
func (c *Client) Open(ctx context.Context, run func(context.Context, apply.Session[*firemon.Config]) error) (opErr, cleanupErr error) {
	dev, err := c.device()
	if err != nil {
		return err, nil
	}
	opErr = dev.WithOperation(ctx, func(ctx context.Context, op *connector.Operation) error {
		return run(ctx, &session{op: op, vendor: c.vendor, parse: c.parse})
	})
	return opErr, dev.Close()
}

// Save persists the running configuration where the platform separates
// saving from changing (Hillstone). It is a no-op for commit platforms.
func (c *Client) Save(ctx context.Context) error {
	if c.vendor == firemon.VendorPaloAlto {
		return nil
	}
	return c.with(ctx, func(ctx context.Context, op *connector.Operation) error {
		_, err := op.SaveConfig(ctx, connector.ExecuteOptions{})
		return err
	})
}

// Device returns the journal identity of the target.
func (c *Client) Device() apply.Device {
	return apply.Device{Host: c.conn.Host, Platform: c.vendor.String()}
}

func (c *Client) with(ctx context.Context, run func(context.Context, *connector.Operation) error) error {
	dev, err := c.device()
	if err != nil {
		return err
	}
	return errors.Join(dev.WithOperation(ctx, run), dev.Close())
}

func (c *Client) device() (*connector.Device, error) {
	d, err := driverFor(c.vendor)
	if err != nil {
		return nil, err
	}
	dev, err := connector.New(d, c.conn)
	if err != nil {
		return nil, fmt.Errorf("netconnector: %w", err)
	}
	return dev, nil
}

func driverFor(v firemon.Vendor) (connector.Driver, error) {
	switch v {
	case firemon.VendorHillstone:
		return nchillstone.New(), nil
	case firemon.VendorPaloAlto:
		return ncpaloalto.New(), nil
	case firemon.VendorUnset:
		return nil, ErrUnsupportedVendor
	default:
		return nil, ErrUnsupportedVendor
	}
}

func runningConfig(ctx context.Context, op *connector.Operation) (string, error) {
	res, err := op.RunningConfig(ctx)
	if err != nil {
		return "", err
	}
	text, ok := res.Config()
	if !ok {
		return "", errors.New("netconnector: device returned no configuration")
	}
	return text, nil
}

// session adapts one connector operation to apply.Session.
type session struct {
	op     *connector.Operation
	vendor firemon.Vendor
	parse  ParseFunc
}

// ReadConfiguration reads and parses the running configuration.
func (s *session) ReadConfiguration(ctx context.Context) (*firemon.Config, error) {
	text, err := runningConfig(ctx, s.op)
	if err != nil {
		return nil, err
	}
	return s.parse(text)
}

// Write sends one deployment write: a single CLI line on Hillstone, a
// whole candidate batch committed at once on PAN-OS.
func (s *session) Write(ctx context.Context, command string) error {
	if s.vendor == firemon.VendorPaloAlto {
		body, err := connector.ParseScript(command, "firemon")
		if err != nil {
			return err
		}
		_, err = s.op.Commit(ctx, body, connector.CommitOptions{})
		return err
	}
	_, err := s.op.ExecuteCommand(ctx, connector.Command{Text: command, Source: "firemon"}, connector.ExecuteOptions{})
	return err
}

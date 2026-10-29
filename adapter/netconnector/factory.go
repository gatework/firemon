package netconnector

import (
	"context"
	"errors"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/device"
	"github.com/gatework/go-net-connector/connector"
)

// Target is supplied by the host's credential/inventory boundary. Credentials
// never enter firewall snapshots or deployment receipts.
type Target struct {
	Metadata      fm.Metadata
	Connection    connector.ConnectionConfig
	DeviceOptions []connector.Option
}

// Factory constructs a fresh Device for every Open, including readback/recovery.
// Resolve must obey its context and return the requested device identity.
type Factory struct {
	Resolve func(context.Context, string) (Target, error)
	Options Options
}

var _ deploy.Factory = Factory{}

func (f Factory) Open(ctx context.Context, id string) (deploy.Session, error) {
	s, err := f.open(ctx, id)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// OpenReadOnly transfers a fresh reader without beginning configuration isolation.
func (f Factory) OpenReadOnly(ctx context.Context, id string) (device.Reader, error) {
	s, err := f.open(ctx, id)
	if err != nil {
		return nil, err
	}
	return &readOnly{Reader: s}, nil
}

// readOnly exposes only capture and resource ownership, even through type assertions.
type readOnly struct{ device.Reader }

func (f Factory) open(ctx context.Context, device string) (*Session, error) {
	if f.Resolve == nil || strings.TrimSpace(device) == "" {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	options, err := f.Options.normalized()
	if err != nil {
		return nil, err
	}
	target, err := f.Resolve(ctx, device)
	if err != nil {
		return nil, err
	}
	if target.Metadata.Device != device {
		return nil, ErrInvalid
	}
	profile, err := Profile(target.Metadata.Vendor)
	if err != nil {
		return nil, err
	}
	if target.Connection.MaxOutputBytes == 0 || target.Connection.MaxOutputBytes > options.MaxOutputBytes {
		target.Connection.MaxOutputBytes = options.MaxOutputBytes
	}
	if target.Connection.MaxScriptOutputBytes == 0 || target.Connection.MaxScriptOutputBytes > options.MaxOutputBytes {
		target.Connection.MaxScriptOutputBytes = options.MaxOutputBytes
	}
	d, err := connector.New(profile, target.Connection, target.DeviceOptions...)
	if err != nil {
		return nil, err
	}
	s, err := New(d, target.Metadata, options)
	if err != nil {
		return nil, errors.Join(err, d.Close())
	}
	if err := d.Connect(ctx); err != nil {
		return nil, errors.Join(err, s.Close())
	}
	return s, nil
}

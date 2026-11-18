package workflow

import (
	"context"
	"errors"
	"os"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/internal/bootstrap"
)

// ConfigReader reads a running configuration from a device.
type ConfigReader interface {
	RunningConfig(ctx context.Context) (string, error)
}

// Source names where a configuration comes from: a file, or a device.
type Source struct {
	Platform bootstrap.Platform
	File     string
	Device   ConfigReader
}

// Loaded is a parsed and compiled configuration.
type Loaded struct {
	Config   *firemon.Config
	Firewall *firemon.Firewall
}

// Load reads, parses and compiles the source.
func Load(ctx context.Context, src Source) (Loaded, error) {
	var text string
	switch {
	case src.File != "":
		raw, err := os.ReadFile(src.File)
		if err != nil {
			return Loaded{}, err
		}
		text = string(raw)
	case src.Device != nil:
		var err error
		if text, err = src.Device.RunningConfig(ctx); err != nil {
			return Loaded{}, err
		}
	default:
		return Loaded{}, errors.New("workflow: a configuration file or a device is required")
	}
	cfg, err := src.Platform.Parse(text)
	if err != nil {
		return Loaded{}, err
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		return Loaded{}, err
	}
	return Loaded{Config: cfg, Firewall: fw}, nil
}

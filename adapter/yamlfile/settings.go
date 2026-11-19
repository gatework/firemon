package yamlfile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"go.yaml.in/yaml/v3"
)

// Settings are the operator's defaults, read from the user configuration
// file (for example ~/.config/firemon/config.yaml), so that everyday
// commands need no repeated flags.
type Settings struct {
	// Store is the snapshot directory.
	Store string `yaml:"store,omitempty"`
	// Inventory is the inventory file.
	Inventory string `yaml:"inventory,omitempty"`
	// Timezone is the IANA zone of the devices' schedules.
	Timezone string `yaml:"timezone,omitempty"`
}

// LoadSettings reads a settings file; a missing file is the zero value.
func LoadSettings(path string) (Settings, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Settings{}, nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("yamlfile: %w", err)
	}
	return ParseSettings(raw)
}

// ParseSettings decodes settings; unknown keys are errors.
func ParseSettings(raw []byte) (Settings, error) {
	var s Settings
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil && !errors.Is(err, io.EOF) {
		return Settings{}, fmt.Errorf("yamlfile: settings: %w", err)
	}
	return s, nil
}

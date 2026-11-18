package yamlfile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"go.yaml.in/yaml/v3"

	"github.com/gatework/firemon/migrate"
)

// LoadMapping reads a migration mapping file.
func LoadMapping(path string) (migrate.Mapping, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return migrate.Mapping{}, fmt.Errorf("yamlfile: %w", err)
	}
	return ParseMapping(raw)
}

// ParseMapping decodes a migration mapping; unknown keys are errors.
func ParseMapping(raw []byte) (migrate.Mapping, error) {
	var m migrate.Mapping
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil && !errors.Is(err, io.EOF) {
		return migrate.Mapping{}, fmt.Errorf("yamlfile: mapping: %w", err)
	}
	return m, nil
}

// WriteMapping encodes a mapping, for example a skeleton to fill in.
func WriteMapping(w io.Writer, m migrate.Mapping) error {
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(m); err != nil {
		return fmt.Errorf("yamlfile: mapping: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("yamlfile: mapping: %w", err)
	}
	return nil
}

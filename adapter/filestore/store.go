package filestore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gatework/firemon"
)

// Errors.
var (
	ErrInvalidName = errors.New("filestore: invalid device name")
	ErrNotFound    = errors.New("filestore: snapshot not found")
	ErrCorrupt     = errors.New("filestore: snapshot does not match its fingerprint")
	// ErrStale reports a snapshot stored by another model version: parse
	// its raw text again and save it.
	ErrStale = errors.New("filestore: snapshot stored by another version")
)

// maxFile bounds every file read from the store.
const maxFile = 256 << 20

const (
	rawFile    = "raw.txt"
	configFile = "config.json"
	metaFile   = "meta.json"
)

// Snapshot is one device's collected configuration.
type Snapshot struct {
	Device      string         `json:"device"`
	Vendor      firemon.Vendor `json:"vendor"`
	Host        string         `json:"host,omitempty"`
	CollectedAt time.Time      `json:"collected_at"`
	Fingerprint string         `json:"fingerprint"`
	// Model is the firemon.ModelVersion the configuration was stored with.
	Model int `json:"model,omitempty"`
	// Config and Raw are stored in their own files.
	Config *firemon.Config `json:"-"`
	Raw    string          `json:"-"`
}

// Files supplies private directories, bounded reads and durable atomic writes.
type Files interface {
	PrepareDirectory(path string) error
	Read(ctx context.Context, path string, limit int64) ([]byte, error)
	Write(ctx context.Context, path string, body []byte) error
}

// Store is a snapshot directory. It is safe for concurrent readers; writers
// of the same device must be serialized by the caller.
type Store struct {
	root  string
	files Files
}

// New opens root, creating it with private permissions when missing.
func New(root string, files Files) (*Store, error) {
	if files == nil {
		return nil, errors.New("filestore: file operations required")
	}
	if err := files.PrepareDirectory(root); err != nil {
		return nil, fmt.Errorf("filestore: %w", err)
	}
	return &Store{root: root, files: files}, nil
}

// Save stores snap as the device's latest snapshot. The fingerprint is
// computed from the configuration.
func (s *Store) Save(ctx context.Context, snap Snapshot) (Snapshot, error) {
	if err := validName(snap.Device); err != nil {
		return Snapshot{}, err
	}
	if snap.Config == nil {
		return Snapshot{}, errors.New("filestore: snapshot without configuration")
	}
	fw, err := firemon.Compile(snap.Config)
	if err != nil {
		return Snapshot{}, err
	}
	snap.Fingerprint, snap.Vendor, snap.Model = fw.Fingerprint(), snap.Config.Vendor, firemon.ModelVersion
	dir := filepath.Join(s.root, snap.Device)
	if err := s.files.PrepareDirectory(dir); err != nil {
		return Snapshot{}, fmt.Errorf("filestore: %w", err)
	}
	config, err := json.Marshal(snap.Config)
	if err != nil {
		return Snapshot{}, fmt.Errorf("filestore: encode configuration: %w", err)
	}
	meta, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return Snapshot{}, fmt.Errorf("filestore: encode metadata: %w", err)
	}
	for _, f := range []struct {
		name string
		body []byte
	}{{rawFile, []byte(snap.Raw)}, {configFile, config}, {metaFile, meta}} {
		if err := s.files.Write(ctx, filepath.Join(dir, f.name), f.body); err != nil {
			return Snapshot{}, fmt.Errorf("filestore: write %s: %w", f.name, err)
		}
	}
	return snap, nil
}

// Load returns the device's latest snapshot with its configuration; Raw is
// left empty (use Raw to read it).
func (s *Store) Load(ctx context.Context, device string) (Snapshot, error) {
	snap, err := s.meta(ctx, device)
	if err != nil {
		return Snapshot{}, err
	}
	if snap.Model != firemon.ModelVersion {
		return snap, ErrStale // the metadata says what to parse again
	}
	body, err := s.files.Read(ctx, filepath.Join(s.root, device, configFile), maxFile)
	if err != nil {
		return Snapshot{}, fmt.Errorf("filestore: read configuration: %w", err)
	}
	var cfg firemon.Config
	if err := json.Unmarshal(body, &cfg); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	if cfg.TimeZone != "" {
		if cfg.Location, err = time.LoadLocation(cfg.TimeZone); err != nil {
			return Snapshot{}, fmt.Errorf("filestore: time zone %q: %w", cfg.TimeZone, err)
		}
	}
	fw, err := firemon.Compile(&cfg)
	if err != nil {
		return Snapshot{}, err
	}
	if fw.Fingerprint() != snap.Fingerprint {
		return Snapshot{}, ErrCorrupt
	}
	snap.Config = &cfg
	return snap, nil
}

// Raw returns the collected configuration text of a device.
func (s *Store) Raw(ctx context.Context, device string) (string, error) {
	if err := validName(device); err != nil {
		return "", err
	}
	body, err := s.files.Read(ctx, filepath.Join(s.root, device, rawFile), maxFile)
	if err != nil {
		return "", fmt.Errorf("filestore: read raw configuration: %w", err)
	}
	return string(body), nil
}

// List returns the metadata of every complete snapshot, ordered by device.
func (s *Store) List(ctx context.Context) ([]Snapshot, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("filestore: %w", err)
	}
	var out []Snapshot
	for _, e := range entries {
		if !e.IsDir() || validName(e.Name()) != nil {
			continue
		}
		snap, err := s.meta(ctx, e.Name())
		if errors.Is(err, ErrNotFound) {
			continue // incomplete: metadata is written last
		}
		if err != nil {
			return nil, err
		}
		out = append(out, snap)
	}
	slices.SortFunc(out, func(a, b Snapshot) int { return strings.Compare(a.Device, b.Device) })
	return out, nil
}

func (s *Store) meta(ctx context.Context, device string) (Snapshot, error) {
	if err := validName(device); err != nil {
		return Snapshot{}, err
	}
	body, err := s.files.Read(ctx, filepath.Join(s.root, device, metaFile), maxFile)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, fmt.Errorf("%w: %s", ErrNotFound, device)
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("filestore: read metadata: %w", err)
	}
	var snap Snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	return snap, nil
}

// validName accepts device names usable as one path element.
func validName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`+"\x00") || len(name) > 128 {
		return fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	return nil
}

package snapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/internal/durablefile"
)

var ErrConflict = errors.New("snapshot revision conflict")
var ErrUnavailable = errors.New("current firewall state is unavailable")
var ErrReserved = errors.New("device has a pending operation")
var ErrNotFound = errors.New("snapshot not found")

type Head struct {
	Networks                                              []flow.Range
	LocationComplete                                      bool
	Revision, SemanticDigest, SourceDigest, PublicationID string
	Generation                                            uint64
	Complete                                              bool
}
type Reservation struct{ Expected, Token string }
type Publication struct {
	Device, Revision string
	Generation       uint64
	Reservation      string
	KeepReservation  bool
}
type Event struct {
	Device, Revision string
	Generation       uint64
	Complete         bool
}
type Manifest struct {
	Version      uint32
	Generation   uint64
	Devices      map[string]Head
	Reservations map[string]Reservation
	Publications map[string]Publication
	Events       []Event
	Acknowledged map[string]uint64
}
type Store struct{ root string }

func (s *Store) validate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.root == "" {
		return ErrInvalid
	}
	return nil
}

func Open(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, ErrInvalid
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Join(abs, "objects"), 0700); err != nil {
		return nil, err
	}
	return &Store{root: abs}, nil
}
func emptyManifest() Manifest {
	return Manifest{Version: 1, Devices: make(map[string]Head), Reservations: make(map[string]Reservation), Publications: make(map[string]Publication), Acknowledged: make(map[string]uint64)}
}
func (s *Store) readManifest() (result Manifest, err error) {
	f, err := os.Open(filepath.Join(s.root, "manifest.json"))
	if errors.Is(err, os.ErrNotExist) {
		return emptyManifest(), nil
	}
	if err != nil {
		return Manifest{}, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	var m Manifest
	decoder := json.NewDecoder(io.LimitReader(f, DefaultMaxBytes))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("%w: manifest: %w", ErrFormat, err)
	}
	if m.Version != 1 || m.Devices == nil || m.Reservations == nil || m.Publications == nil || m.Acknowledged == nil {
		return Manifest{}, ErrFormat
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return Manifest{}, ErrFormat
	}
	return m, nil
}

// Manifest always reads persisted state, including cross-process reservations.
func (s *Store) Manifest(ctx context.Context) (Manifest, error) {
	if err := s.validate(ctx); err != nil {
		return Manifest{}, err
	}
	return s.readManifest()
}
func atomicWrite(path string, data []byte) error { return durablefile.Replace(path, data) }
func (s *Store) writeManifest(m Manifest) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.root, "manifest.json"), data)
}
func validRevision(revision string) bool {
	if len(revision) != 64 {
		return false
	}
	_, err := hex.DecodeString(revision)
	return err == nil && strings.ToLower(revision) == revision
}
func (s *Store) Load(ctx context.Context, revision string) (result *fm.Firewall, err error) {
	if err := s.validate(ctx); err != nil {
		return nil, err
	}
	if !validRevision(revision) {
		return nil, ErrInvalid
	}
	f, err := os.Open(filepath.Join(s.root, "objects", revision+".gob"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	h := sha256.New()
	fw, err := Decode(io.TeeReader(f, h), DefaultMaxBytes)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(h.Sum(nil)) != revision {
		return nil, ErrFormat
	}
	return fw, ctx.Err()
}
func (s *Store) Current(ctx context.Context, device string) (*fm.Firewall, Head, error) {
	if err := s.validate(ctx); err != nil {
		return nil, Head{}, err
	}
	if strings.TrimSpace(device) == "" {
		return nil, Head{}, ErrInvalid
	}
	m, err := s.Manifest(ctx)
	if err != nil {
		return nil, Head{}, err
	}
	h, ok := m.Devices[device]
	if !ok {
		return nil, Head{}, ErrNotFound
	}
	if _, reserved := m.Reservations[device]; reserved || !h.Complete {
		return nil, h, ErrUnavailable
	}
	if !validRevision(h.Revision) {
		return nil, h, ErrFormat
	}
	fw, err := s.Load(ctx, h.Revision)
	if err != nil {
		return nil, h, err
	}
	if fw.Metadata().Device != device || !fw.Complete() || h.SemanticDigest != fw.SemanticDigest() || h.SourceDigest != fw.Metadata().SourceDigest {
		return nil, h, ErrFormat
	}
	return fw, h, nil
}

type PublishOptions struct {
	Expected, PublicationID, Reservation string
	Live                                 bool
	// KeepReservation archives observed live changes while retaining operation
	// ownership. Recovery must prove the state before releasing this reservation.
	KeepReservation bool
}
type PublishResult struct {
	Revision   string
	Generation uint64
	Archived   bool
}

func (s *Store) Publish(ctx context.Context, fw *fm.Firewall, options PublishOptions) (result PublishResult, err error) {
	if err := s.validate(ctx); err != nil {
		return PublishResult{}, err
	}
	if fw == nil || strings.TrimSpace(options.PublicationID) == "" || options.Expected != "" && !validRevision(options.Expected) || options.KeepReservation && (!options.Live || strings.TrimSpace(options.Reservation) == "") {
		return PublishResult{}, ErrInvalid
	}

	object, err := encodeBlob(fw)
	if err != nil {
		return PublishResult{}, err
	}
	revision := object.revision
	device := fw.Metadata().Device
	unlock, err := lock(ctx, filepath.Join(s.root, "manifest.lock"))
	if err != nil {
		return PublishResult{}, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	m, err := s.readManifest()
	if err != nil {
		return PublishResult{}, err
	}
	if prior, ok := m.Publications[options.PublicationID]; ok {
		if prior.Device != device || prior.Revision != revision || prior.Reservation != options.Reservation || prior.KeepReservation != options.KeepReservation {
			return PublishResult{}, ErrConflict
		}
		return PublishResult{Revision: prior.Revision, Generation: prior.Generation}, nil
	}
	head := m.Devices[device]
	if head.Revision != options.Expected {
		return PublishResult{}, ErrConflict
	}
	if reservation, ok := m.Reservations[device]; ok {
		if reservation.Token != options.Reservation {
			return PublishResult{}, ErrReserved
		}
	} else if options.Reservation != "" {
		return PublishResult{}, ErrReserved
	}
	// A crash before manifest replacement leaves only an unreferenced immutable blob.
	if err := s.storeBlob(ctx, object); err != nil {
		return PublishResult{}, err
	}
	if !fw.Complete() && !options.Live {
		return PublishResult{Revision: revision, Generation: m.Generation, Archived: true}, nil
	}
	if err := s.validate(ctx); err != nil {
		return PublishResult{}, err
	}
	m.Generation++
	networks := networkSummary(fw)
	m.Devices[device] = Head{Networks: networks, LocationComplete: fw.Complete() && len(networks) > 0, Revision: revision, SemanticDigest: fw.SemanticDigest(), SourceDigest: fw.Metadata().SourceDigest, PublicationID: options.PublicationID, Generation: m.Generation, Complete: fw.Complete()}
	m.Publications[options.PublicationID] = Publication{Device: device, Revision: revision, Generation: m.Generation, Reservation: options.Reservation, KeepReservation: options.KeepReservation}
	m.Events = append(m.Events, Event{Device: device, Revision: revision, Generation: m.Generation, Complete: fw.Complete()})
	if options.KeepReservation {
		m.Reservations[device] = Reservation{Expected: revision, Token: options.Reservation}
	} else {
		delete(m.Reservations, device)
	}
	if err = s.writeManifest(m); err != nil {
		return PublishResult{}, err
	}
	return PublishResult{Revision: revision, Generation: m.Generation}, nil
}
func (s *Store) Reserve(ctx context.Context, device, expected, token string) (err error) {
	if err := s.validate(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(token) == "" || strings.TrimSpace(device) == "" || !validRevision(expected) {
		return ErrInvalid
	}
	unlock, err := lock(ctx, filepath.Join(s.root, "manifest.lock"))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	m, err := s.readManifest()
	if err != nil {
		return err
	}
	h, ok := m.Devices[device]
	if !ok || h.Revision != expected || !h.Complete {
		return ErrConflict
	}
	if r, ok := m.Reservations[device]; ok {
		if r.Token == token && r.Expected == expected {
			return nil
		}
		return ErrReserved
	}
	m.Reservations[device] = Reservation{Expected: expected, Token: token}
	m.Generation++
	return s.writeManifest(m)
}

// ReleaseUnchanged requires an independently confirmed baseline revision, never a timeout.
func (s *Store) ReleaseUnchanged(ctx context.Context, device, token, confirmedRevision string) (err error) {
	if err := s.validate(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(device) == "" || strings.TrimSpace(token) == "" || !validRevision(confirmedRevision) {
		return ErrInvalid
	}
	unlock, err := lock(ctx, filepath.Join(s.root, "manifest.lock"))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	m, err := s.readManifest()
	if err != nil {
		return err
	}
	r, ok := m.Reservations[device]
	if !ok || r.Token != token {
		return ErrReserved
	}
	if r.Expected != confirmedRevision || m.Devices[device].Revision != confirmedRevision {
		return ErrConflict
	}
	if !m.Devices[device].Complete {
		return ErrUnavailable
	}
	delete(m.Reservations, device)
	m.Generation++
	return s.writeManifest(m)
}

// Archive stores immutable captured evidence without publishing a current head,
// releasing a reservation or emitting a projection event.
func (s *Store) Archive(ctx context.Context, fw *fm.Firewall) (string, error) {
	if err := s.validate(ctx); err != nil {
		return "", err
	}
	object, err := encodeBlob(fw)
	if err != nil {
		return "", err
	}
	if err := s.storeBlob(ctx, object); err != nil {
		return "", err
	}
	return object.revision, ctx.Err()
}

// Acknowledge advances a sink cursor with CAS. Sinks apply each batch idempotently before this call.
func (s *Store) Acknowledge(ctx context.Context, sink string, expected, next uint64) (err error) {
	if err := s.validate(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(sink) == "" || next < expected {
		return ErrInvalid
	}
	unlock, err := lock(ctx, filepath.Join(s.root, "manifest.lock"))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	m, err := s.readManifest()
	if err != nil {
		return err
	}
	if m.Acknowledged[sink] != expected || next > m.Generation {
		return ErrConflict
	}
	m.Acknowledged[sink] = next
	return s.writeManifest(m)
}

func networkSummary(fw *fm.Firewall) []flow.Range {
	var ranges []flow.Range
	for _, i := range fw.Interfaces() {
		r := i.Record()
		if r.Disabled {
			continue
		}
		for _, p := range r.Addresses {
			if network, err := flow.PrefixRange(p); err == nil {
				ranges = append(ranges, network)
			}
		}
	}
	for _, r := range fw.Routes() {
		if network, err := flow.PrefixRange(r.Record().Destination); err == nil {
			ranges = append(ranges, network)
		}
	}
	for _, z := range fw.Zones() {
		ranges = append(ranges, z.Record().Networks...)
	}
	set, _ := flow.NewSet(ranges...)
	return set.Ranges()
}

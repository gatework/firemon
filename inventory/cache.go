package inventory

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"slices"
	"strings"
	"sync"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/snapshot"
)

// Source loads verified immutable revisions and the current persisted manifest.
// The manifest remains authoritative for publication and reservation state.
type Source interface {
	ManifestReader
	RevisionLoader
}

// CacheLimits bounds retained graphs and indexes. Source bytes and declaration
// counts are separate accounting units, not an estimate of Go heap bytes.
// MaxEntries also bounds simultaneous graph loads and index builds separately;
// MaxDeclarations bounds each index build and lookup's visited ranges.
// Zero selects defaults: 64 entries, 128 MiB of source, 1,000,000 declarations.
type CacheLimits struct {
	MaxEntries      int
	MaxSourceBytes  int64
	MaxDeclarations int
}

const (
	defaultCacheEntries      = 64
	defaultCacheSourceBytes  = 128 << 20
	defaultCacheDeclarations = 1_000_000
)

// Cache reuses immutable firewall objects across queries. It does not cache
// manifests, policy outcomes, time evaluations or device reads. It is safe for
// concurrent use and must not be copied after construction.
type Cache struct {
	source Source
	limits CacheLimits

	mu           sync.Mutex
	graphs       map[string]*list.Element
	order        list.List
	pending      map[string]*cacheLoad
	indexing     map[*fm.Firewall]*indexLoad
	changed      chan struct{}
	sourceBytes  int64
	declarations int
}

type cachedGraph struct {
	revision     string
	firewall     *fm.Firewall
	index        *Index
	sourceBytes  int64
	declarations int
}

type cacheLoad struct {
	done     chan struct{}
	firewall *fm.Firewall
	err      error
	retry    bool
}

func NewCache(source Source, limits CacheLimits) (*Cache, error) {
	if dependency.Nil(source) || limits.MaxEntries < 0 || limits.MaxSourceBytes < 0 || limits.MaxDeclarations < 0 {
		return nil, ErrInvalid
	}
	if limits.MaxEntries == 0 {
		limits.MaxEntries = defaultCacheEntries
	}
	if limits.MaxSourceBytes == 0 {
		limits.MaxSourceBytes = defaultCacheSourceBytes
	}
	if limits.MaxDeclarations == 0 {
		limits.MaxDeclarations = defaultCacheDeclarations
	}
	return &Cache{
		source: source, limits: limits,
		graphs: make(map[string]*list.Element), pending: make(map[string]*cacheLoad),
		indexing: make(map[*fm.Firewall]*indexLoad), changed: make(chan struct{}),
	}, nil
}

func (c *Cache) validate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil || dependency.Nil(c.source) || c.limits.MaxEntries == 0 {
		return ErrInvalid
	}
	return nil
}

// Manifest reads publication and reservation state every time and returns owned
// containers. A caller may pin this result for the duration of one batch.
func (c *Cache) Manifest(ctx context.Context) (snapshot.Manifest, error) {
	if err := c.validate(ctx); err != nil {
		return snapshot.Manifest{}, err
	}
	m, err := c.source.Manifest(ctx)
	if err != nil {
		return snapshot.Manifest{}, err
	}
	if err := ctx.Err(); err != nil {
		return snapshot.Manifest{}, err
	}
	if m.Version != 1 || m.Devices == nil || m.Reservations == nil {
		return snapshot.Manifest{}, snapshot.ErrFormat
	}
	m.Devices = maps.Clone(m.Devices)
	for device, head := range m.Devices {
		head.Networks = slices.Clone(head.Networks)
		m.Devices[device] = head
	}
	m.Reservations = maps.Clone(m.Reservations)
	m.Publications = maps.Clone(m.Publications)
	m.Events = slices.Clone(m.Events)
	m.Acknowledged = maps.Clone(m.Acknowledged)
	if err := ctx.Err(); err != nil {
		return snapshot.Manifest{}, err
	}
	return m, nil
}

// Load shares one verified graph per revision. A canceled loading caller owns
// its I/O; independent waiters retry with their own contexts. No background
// goroutine or context detached from a caller is needed. A graph larger than a
// retention limit is returned normally without evicting useful cached objects.
func (c *Cache) Load(ctx context.Context, revision string) (*fm.Firewall, error) {
	if err := c.validate(ctx); err != nil {
		return nil, err
	}
	if !cacheRevision(revision) {
		return nil, snapshot.ErrInvalid
	}
	for {
		c.mu.Lock()
		if err := ctx.Err(); err != nil {
			c.mu.Unlock()
			return nil, err
		}
		if element := c.graphs[revision]; element != nil {
			c.order.MoveToFront(element)
			fw := element.Value.(cachedGraph).firewall
			c.mu.Unlock()
			return fw, nil
		}
		if pending := c.pending[revision]; pending != nil {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-pending.done:
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if pending.retry {
				continue
			}
			return pending.firewall, pending.err
		}
		if len(c.pending) >= c.limits.MaxEntries {
			changed := c.changed
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-changed:
				continue
			}
		}
		pending := &cacheLoad{done: make(chan struct{})}
		c.pending[revision] = pending
		c.mu.Unlock()
		return c.load(ctx, revision, pending)
	}
}

func (c *Cache) load(ctx context.Context, revision string, pending *cacheLoad) (*fm.Firewall, error) {
	fw, err := c.source.Load(ctx, revision)
	if err == nil && (fw == nil || fw.SemanticDigest() == "" || fw.Metadata().Device == "" || fw.Metadata().Vendor == "") {
		err = snapshot.ErrFormat
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if canceled := ctx.Err(); canceled != nil {
		err = canceled
		pending.retry = true
	}
	if err != nil {
		fw = nil
	} else {
		c.retain(revision, fw, nil)
	}
	pending.firewall, pending.err = fw, err
	delete(c.pending, revision)
	close(pending.done)
	close(c.changed)
	c.changed = make(chan struct{})
	return fw, err
}

// retain is called with the mutex held. Subtraction avoids overflow when a host
// chooses large limits. Only cachedGraph values are stored in the private list.
func (c *Cache) retain(revision string, fw *fm.Firewall, index *Index) {
	entry := cachedGraph{
		revision: revision, firewall: fw, index: index,
		sourceBytes: int64(len(fw.Raw())), declarations: fw.DeclarationSize(),
	}
	if entry.sourceBytes > c.limits.MaxSourceBytes || entry.declarations > c.limits.MaxDeclarations {
		return
	}
	if index != nil {
		if index.cost > c.limits.MaxDeclarations-entry.declarations {
			return
		}
		entry.declarations += index.cost
	}
	if previous := c.graphs[revision]; previous != nil {
		c.remove(previous)
	}
	for len(c.graphs) >= c.limits.MaxEntries || entry.sourceBytes > c.limits.MaxSourceBytes-c.sourceBytes || entry.declarations > c.limits.MaxDeclarations-c.declarations {
		c.remove(c.order.Back())
	}
	c.graphs[revision] = c.order.PushFront(entry)
	c.sourceBytes += entry.sourceBytes
	c.declarations += entry.declarations
}

func (c *Cache) remove(element *list.Element) {
	old := c.order.Remove(element).(cachedGraph)
	delete(c.graphs, old.revision)
	c.sourceBytes -= old.sourceBytes
	c.declarations -= old.declarations
}

// Current resolves one current, complete, unreserved graph. The same identity
// and digest checks as snapshot.Store.Current apply even when Load is a hit.
func (c *Cache) Current(ctx context.Context, device string) (*fm.Firewall, snapshot.Head, error) {
	if err := c.validate(ctx); err != nil {
		return nil, snapshot.Head{}, err
	}
	if strings.TrimSpace(device) == "" {
		return nil, snapshot.Head{}, ErrInvalid
	}
	m, err := c.Manifest(ctx)
	if err != nil {
		return nil, snapshot.Head{}, err
	}
	head, ok := m.Devices[device]
	if !ok {
		return nil, snapshot.Head{}, snapshot.ErrNotFound
	}
	if _, reserved := m.Reservations[device]; reserved || !head.Complete {
		return nil, head, snapshot.ErrUnavailable
	}
	if !cacheRevision(head.Revision) {
		return nil, head, snapshot.ErrFormat
	}
	fw, err := c.Load(ctx, head.Revision)
	if err != nil {
		return nil, head, err
	}
	meta := fw.Metadata()
	if meta.Device != device || !fw.Complete() || head.SemanticDigest != fw.SemanticDigest() || head.SourceDigest != meta.SourceDigest {
		return nil, head, snapshot.ErrFormat
	}
	return fw, head, nil
}

func cacheRevision(revision string) bool {
	if len(revision) != sha256.Size*2 || strings.ToLower(revision) != revision {
		return false
	}
	var digest [sha256.Size]byte
	_, err := hex.Decode(digest[:], []byte(revision))
	return err == nil
}

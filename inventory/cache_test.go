package inventory_test

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/snapshot"
)

type cacheSource struct {
	manifest func(context.Context) (snapshot.Manifest, error)
	load     func(context.Context, string) (*fm.Firewall, error)
}

func (s *cacheSource) Manifest(ctx context.Context) (snapshot.Manifest, error) {
	return s.manifest(ctx)
}

func (s *cacheSource) Load(ctx context.Context, revision string) (*fm.Firewall, error) {
	return s.load(ctx, revision)
}

func cacheGraph(t testing.TB, name, raw string) *fm.Firewall {
	t.Helper()
	fw, err := fm.Seal(fm.Data{
		Metadata: fm.Metadata{Device: name, Vendor: "hillstone"},
		Raw:      raw,
		Addresses: []fm.AddressRecord{{
			Object: fm.Object{ID: "host", Name: "host"},
			Ranges: []flow.AddressRange{{
				First: netip.MustParseAddr("192.0.2.10"),
				Last:  netip.MustParseAddr("192.0.2.10"),
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func cacheHead(fw *fm.Firewall, revision string) snapshot.Head {
	return snapshot.Head{
		Revision: revision, SemanticDigest: fw.SemanticDigest(),
		SourceDigest: fw.Metadata().SourceDigest, Complete: fw.Complete(),
	}
}

func TestCacheCurrentUsesFreshManifestAndImmutableRevisions(t *testing.T) {
	store, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	before := cacheGraph(t, "lab", "synthetic before")
	first, err := store.Publish(t.Context(), before, snapshot.PublishOptions{PublicationID: "before"})
	if err != nil {
		t.Fatal(err)
	}
	var reads, loads atomic.Int64
	source := &cacheSource{
		manifest: func(ctx context.Context) (snapshot.Manifest, error) {
			reads.Add(1)
			return store.Manifest(ctx)
		},
		load: func(ctx context.Context, revision string) (*fm.Firewall, error) {
			loads.Add(1)
			return store.Load(ctx, revision)
		},
	}
	cache, err := inventory.NewCache(source, inventory.CacheLimits{})
	if err != nil {
		t.Fatal(err)
	}
	one, head, err := cache.Current(t.Context(), "lab")
	if err != nil || head.Revision != first.Revision {
		t.Fatal(head, err)
	}
	two, _, err := cache.Current(t.Context(), "lab")
	if err != nil || one != two || loads.Load() != 1 || reads.Load() != 2 {
		t.Fatal("current did not share the immutable graph behind a fresh manifest", err)
	}
	exported := one.Export()
	exported.Addresses[0].Ranges[0].First = netip.MustParseAddr("203.0.113.1")
	if two.Address("host").Record().Ranges[0].First != netip.MustParseAddr("192.0.2.10") {
		t.Fatal("a reader changed the cached graph")
	}
	after := cacheGraph(t, "lab", "synthetic after")
	second, err := store.Publish(t.Context(), after, snapshot.PublishOptions{Expected: first.Revision, PublicationID: "after"})
	if err != nil {
		t.Fatal(err)
	}
	three, head, err := cache.Current(t.Context(), "lab")
	if err != nil || head.Revision != second.Revision || three == one || loads.Load() != 2 {
		t.Fatal("cache concealed a newly published revision", head, err)
	}
	old, err := cache.Load(t.Context(), first.Revision)
	if err != nil || old != one || loads.Load() != 2 || old.Raw() != "synthetic before" {
		t.Fatal("an in-flight old revision changed", err)
	}
}

func TestCacheManifestOwnsEveryContainer(t *testing.T) {
	network := flow.AddressRange{First: netip.MustParseAddr("192.0.2.0"), Last: netip.MustParseAddr("192.0.2.255")}
	manifest := snapshot.Manifest{
		Version: 1, Generation: 3,
		Devices:      map[string]snapshot.Head{"lab": {Networks: []flow.AddressRange{network}}},
		Reservations: map[string]snapshot.Reservation{"lab": {Token: "reservation"}},
		Publications: map[string]snapshot.Publication{"publish": {Device: "lab"}},
		Events:       []snapshot.Event{{Device: "lab"}},
		Acknowledged: map[string]uint64{"sink": 2},
	}
	source := &cacheSource{manifest: func(context.Context) (snapshot.Manifest, error) { return manifest, nil }}
	cache, err := inventory.NewCache(source, inventory.CacheLimits{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := cache.Manifest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got.Devices["lab"].Networks[0] = flow.AddressRange{}
	delete(got.Devices, "lab")
	delete(got.Reservations, "lab")
	delete(got.Publications, "publish")
	got.Events[0].Device = "changed"
	got.Acknowledged["sink"] = 99
	if manifest.Devices["lab"].Networks[0] != network || len(manifest.Reservations) != 1 || len(manifest.Publications) != 1 || manifest.Events[0].Device != "lab" || manifest.Acknowledged["sink"] != 2 {
		t.Fatal("manifest containers alias the source")
	}
}

func TestCacheCurrentCannotBypassUnavailableOrChangedEvidence(t *testing.T) {
	fw := cacheGraph(t, "lab", "synthetic")
	revision := strings.Repeat("a", 64)
	head := cacheHead(fw, revision)
	manifest := snapshot.Manifest{Version: 1, Devices: map[string]snapshot.Head{"lab": head}, Reservations: map[string]snapshot.Reservation{}}
	loads := 0
	source := &cacheSource{
		manifest: func(context.Context) (snapshot.Manifest, error) { return manifest, nil },
		load: func(context.Context, string) (*fm.Firewall, error) {
			loads++
			return fw, nil
		},
	}
	cache, err := inventory.NewCache(source, inventory.CacheLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cache.Current(t.Context(), "lab"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func()
		err    error
	}{
		{"reserved", func() { manifest.Reservations["lab"] = snapshot.Reservation{Token: "operation"} }, snapshot.ErrUnavailable},
		{"incomplete", func() { h := head; h.Complete = false; manifest.Devices["lab"] = h }, snapshot.ErrUnavailable},
		{"missing", func() { delete(manifest.Devices, "lab") }, snapshot.ErrNotFound},
		{"invalid revision", func() { h := head; h.Revision = "invalid"; manifest.Devices["lab"] = h }, snapshot.ErrFormat},
		{"semantic digest", func() { h := head; h.SemanticDigest = "changed"; manifest.Devices["lab"] = h }, snapshot.ErrFormat},
		{"source digest", func() { h := head; h.SourceDigest = "changed"; manifest.Devices["lab"] = h }, snapshot.ErrFormat},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest.Devices = map[string]snapshot.Head{"lab": head}
			manifest.Reservations = map[string]snapshot.Reservation{}
			test.change()
			if got, _, err := cache.Current(t.Context(), "lab"); got != nil || !errors.Is(err, test.err) {
				t.Fatal(got, err)
			}
			if loads != 1 {
				t.Fatal("cached evidence should be checked without reloading", loads)
			}
		})
	}
	manifest.Devices = map[string]snapshot.Head{"other": head}
	if got, _, err := cache.Current(t.Context(), "other"); got != nil || !errors.Is(err, snapshot.ErrFormat) {
		t.Fatal("wrong device identity accepted", err)
	}
}

func TestCacheEvictsLeastRecentlyUsedWithinEveryLimit(t *testing.T) {
	graphs := map[string]*fm.Firewall{}
	for _, letter := range []string{"a", "b", "c"} {
		graphs[strings.Repeat(letter, 64)] = cacheGraph(t, letter, "synthetic")
	}
	for _, test := range []struct {
		name   string
		limits inventory.CacheLimits
	}{
		{"entries", inventory.CacheLimits{MaxEntries: 2}},
		{"source bytes", inventory.CacheLimits{MaxSourceBytes: 2 * int64(len(graphs[strings.Repeat("a", 64)].Raw()))}},
		{"declarations", inventory.CacheLimits{MaxDeclarations: 2 * graphs[strings.Repeat("a", 64)].DeclarationSize()}},
	} {
		t.Run(test.name, func(t *testing.T) {
			loads := map[string]int{}
			source := &cacheSource{load: func(_ context.Context, revision string) (*fm.Firewall, error) {
				loads[revision]++
				return graphs[revision], nil
			}}
			cache, err := inventory.NewCache(source, test.limits)
			if err != nil {
				t.Fatal(err)
			}
			for _, letter := range []string{"a", "b", "a", "c", "a", "b"} {
				if _, err := cache.Load(t.Context(), strings.Repeat(letter, 64)); err != nil {
					t.Fatal(err)
				}
			}
			want := map[string]int{strings.Repeat("a", 64): 1, strings.Repeat("b", 64): 2, strings.Repeat("c", 64): 1}
			if !maps.Equal(loads, want) {
				t.Fatal(loads)
			}
		})
	}
}

func TestCacheServesOversizedGraphsWithoutRetainingThem(t *testing.T) {
	fw := cacheGraph(t, "lab", "synthetic")
	for _, limits := range []inventory.CacheLimits{{MaxSourceBytes: 1}, {MaxDeclarations: 1}} {
		loads := 0
		source := &cacheSource{load: func(context.Context, string) (*fm.Firewall, error) {
			loads++
			return fw, nil
		}}
		cache, err := inventory.NewCache(source, limits)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if got, err := cache.Load(t.Context(), strings.Repeat("a", 64)); err != nil || got != fw {
				t.Fatal(got, err)
			}
		}
		if loads != 2 {
			t.Fatal("oversized graph was retained", loads)
		}
	}
}

func TestCacheConcurrentLoadSharesOneRead(t *testing.T) {
	fw := cacheGraph(t, "lab", "synthetic")
	var calls atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	source := &cacheSource{load: func(ctx context.Context, _ string) (*fm.Firewall, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			return fw, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	cache, err := inventory.NewCache(source, inventory.CacheLimits{})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if got, err := cache.Load(t.Context(), strings.Repeat("a", 64)); err != nil || got != fw {
				t.Error(got, err)
			}
		})
	}
	<-started
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("concurrent requests reloaded one revision", calls.Load())
	}
}

// Done records when Load has reached a cancellable wait, without a timed sleep.
type cacheWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *cacheWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestCacheOwnerCancellationDoesNotPoisonWaiter(t *testing.T) {
	fw := cacheGraph(t, "lab", "synthetic")
	var calls atomic.Int64
	started := make(chan struct{})
	source := &cacheSource{load: func(ctx context.Context, _ string) (*fm.Firewall, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return fw, nil
	}}
	cache, err := inventory.NewCache(source, inventory.CacheLimits{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	owner := make(chan error, 1)
	go func() { _, err := cache.Load(ctx, strings.Repeat("a", 64)); owner <- err }()
	<-started
	waiter := &cacheWaitContext{Context: t.Context(), waiting: make(chan struct{})}
	done := make(chan error, 1)
	go func() { _, err := cache.Load(waiter, strings.Repeat("a", 64)); done <- err }()
	<-waiter.waiting
	cancel()
	if err := <-owner; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal("independent waiter inherited the owner's cancellation", err)
	}
	if calls.Load() != 2 {
		t.Fatal("the surviving waiter should retry under its own context", calls.Load())
	}
}

func TestCacheWaiterCancellationDoesNotCancelRead(t *testing.T) {
	fw := cacheGraph(t, "lab", "synthetic")
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	source := &cacheSource{load: func(ctx context.Context, _ string) (*fm.Firewall, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			return fw, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	cache, err := inventory.NewCache(source, inventory.CacheLimits{})
	if err != nil {
		t.Fatal(err)
	}
	owner := make(chan error, 1)
	go func() { _, err := cache.Load(t.Context(), strings.Repeat("a", 64)); owner <- err }()
	<-started
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	waiter := &cacheWaitContext{Context: ctx, waiting: make(chan struct{})}
	done := make(chan error, 1)
	go func() { _, err := cache.Load(waiter, strings.Repeat("a", 64)); done <- err }()
	<-waiter.waiting
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	if err := <-owner; err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Load(t.Context(), strings.Repeat("a", 64)); err != nil || calls.Load() != 1 {
		t.Fatal("canceled waiter interrupted the shared read", err)
	}
}

func TestCacheFailureAndInvalidInputsAreNotCached(t *testing.T) {
	var nilSource *cacheSource
	for _, source := range []inventory.Source{nil, nilSource} {
		if _, err := inventory.NewCache(source, inventory.CacheLimits{}); !errors.Is(err, inventory.ErrInvalid) {
			t.Fatal(err)
		}
	}
	source := &cacheSource{}
	for _, limits := range []inventory.CacheLimits{{MaxEntries: -1}, {MaxSourceBytes: -1}, {MaxDeclarations: -1}} {
		if _, err := inventory.NewCache(source, limits); !errors.Is(err, inventory.ErrInvalid) {
			t.Fatal(err)
		}
	}
	fw := cacheGraph(t, "lab", "synthetic")
	failure := errors.New("synthetic read failure")
	calls := 0
	source.load = func(context.Context, string) (*fm.Firewall, error) {
		calls++
		switch calls {
		case 1:
			return fw, failure
		case 2:
			return nil, nil
		case 3:
			return &fm.Firewall{}, nil
		default:
			return fw, nil
		}
	}
	cache, err := inventory.NewCache(source, inventory.CacheLimits{})
	if err != nil {
		t.Fatal(err)
	}
	revision := strings.Repeat("a", 64)
	for _, expected := range []error{failure, snapshot.ErrFormat, snapshot.ErrFormat, nil, nil} {
		got, err := cache.Load(t.Context(), revision)
		if !errors.Is(err, expected) || expected != nil && got != nil {
			t.Fatal(got, err)
		}
	}
	if calls != 4 {
		t.Fatal("failure was cached", calls)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := cache.Load(ctx, revision); got != nil || !errors.Is(err, context.Canceled) || calls != 4 {
		t.Fatal("cache hit ignored cancellation", err)
	}
	var empty *inventory.Cache
	for _, c := range []*inventory.Cache{empty, {}} {
		if _, err := c.Load(t.Context(), revision); !errors.Is(err, inventory.ErrInvalid) {
			t.Fatal(err)
		}
		if _, err := c.Manifest(t.Context()); !errors.Is(err, inventory.ErrInvalid) {
			t.Fatal(err)
		}
		if _, _, err := c.Current(t.Context(), "lab"); !errors.Is(err, inventory.ErrInvalid) {
			t.Fatal(err)
		}
	}
}

func TestCacheBoundsDistinctConcurrentLoadsAndWaitsWithContext(t *testing.T) {
	fw := cacheGraph(t, "lab", "synthetic")
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	source := &cacheSource{load: func(ctx context.Context, revision string) (*fm.Firewall, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			return fw, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	cache, err := inventory.NewCache(source, inventory.CacheLimits{MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	owner := make(chan error, 1)
	go func() { _, err := cache.Load(t.Context(), strings.Repeat("a", 64)); owner <- err }()
	<-started
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	waiter := &cacheWaitContext{Context: ctx, waiting: make(chan struct{})}
	done := make(chan error, 1)
	go func() { _, err := cache.Load(waiter, strings.Repeat("b", 64)); done <- err }()
	<-waiter.waiting
	if calls.Load() != 1 {
		t.Fatal("cache started too many different loads", calls.Load())
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("waiting for a load slot ignored cancellation", err)
	}
	close(release)
	if err := <-owner; err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Load(t.Context(), strings.Repeat("b", 64)); err != nil || calls.Load() != 2 {
		t.Fatal("a completed load did not release its slot", err)
	}
}

func TestCacheRejectsBadRevisionsAndCanceledSourceResults(t *testing.T) {
	fw := cacheGraph(t, "lab", "synthetic")
	var calls int
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	source := &cacheSource{load: func(context.Context, string) (*fm.Firewall, error) {
		calls++
		cancel()
		return fw, nil
	}}
	cache, err := inventory.NewCache(source, inventory.CacheLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, revision := range []string{"", "revision", strings.Repeat("A", 64), strings.Repeat("x", 64)} {
		if got, err := cache.Load(t.Context(), revision); got != nil || !errors.Is(err, snapshot.ErrInvalid) {
			t.Fatal("invalid revision reached source", revision, err)
		}
	}
	if calls != 0 {
		t.Fatal(calls)
	}
	if got, err := cache.Load(ctx, strings.Repeat("a", 64)); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled callback yielded a graph", err)
	}
	if _, err := cache.Load(t.Context(), strings.Repeat("a", 64)); err != nil || calls != 2 {
		t.Fatal("canceled callback was cached", err)
	}
}

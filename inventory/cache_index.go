package inventory

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/snapshot"
)

type indexLoad struct {
	done  chan struct{}
	index *Index
	err   error
	retry bool
}

// Index derives an address index from an already loaded immutable revision.
// It never reloads the graph or admits the supplied graph into the source cache.
// An index is retained only alongside that same graph in its revision's LRU
// entry; callers may keep it for a batch even when the entry cannot be retained.
func (c *Cache) Index(ctx context.Context, revision string, fw *fm.Firewall) (*Index, error) {
	if err := c.validate(ctx); err != nil {
		return nil, err
	}
	if !cacheRevision(revision) || fw == nil || fw.SemanticDigest() == "" {
		return nil, snapshot.ErrInvalid
	}
	for {
		c.mu.Lock()
		if err := ctx.Err(); err != nil {
			c.mu.Unlock()
			return nil, err
		}
		if element := c.graphs[revision]; element != nil {
			entry := element.Value.(cachedGraph)
			if entry.firewall == fw && entry.index != nil {
				c.order.MoveToFront(element)
				c.mu.Unlock()
				return entry.index, nil
			}
		}
		if pending := c.indexing[fw]; pending != nil {
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
			return pending.index, pending.err
		}
		if len(c.indexing) >= c.limits.MaxEntries {
			changed := c.changed
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-changed:
				continue
			}
		}
		pending := &indexLoad{done: make(chan struct{})}
		c.indexing[fw] = pending
		c.mu.Unlock()
		index, err := buildIndex(ctx, fw, c.limits.MaxDeclarations)
		c.mu.Lock()
		if canceled := ctx.Err(); canceled != nil {
			err = canceled
			pending.retry = true
		}
		if err != nil {
			index = nil
		} else if element := c.graphs[revision]; element != nil && element.Value.(cachedGraph).firewall == fw {
			c.retain(revision, fw, index)
		}
		pending.index, pending.err = index, err
		delete(c.indexing, fw)
		close(pending.done)
		close(c.changed)
		c.changed = make(chan struct{})
		c.mu.Unlock()
		return index, err
	}
}

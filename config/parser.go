package config

import (
	"context"

	fm "github.com/gatework/firemon"
)

// Parser seals native source into an immutable firewall graph.
type Parser interface {
	Parse(context.Context, Source, fm.Metadata) (*fm.Firewall, error)
}

type ParseFunc func(context.Context, Source, fm.Metadata) (*fm.Firewall, error)

func (f ParseFunc) Parse(ctx context.Context, source Source, metadata fm.Metadata) (*fm.Firewall, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f == nil {
		return nil, ErrInvalid
	}
	return f(ctx, source, metadata)
}

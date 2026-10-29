//go:build darwin || linux || freebsd || openbsd || netbsd

package snapshot

import (
	"context"
	"github.com/gatework/firemon/internal/durablefile"
)

func lock(ctx context.Context, path string) (func() error, error) { return durablefile.Lock(ctx, path) }

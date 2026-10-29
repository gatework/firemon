//go:build darwin || linux || freebsd || openbsd || netbsd

package deploy

import (
	"context"
	"github.com/gatework/firemon/internal/durablefile"
)

func journalLock(ctx context.Context, path string) (func() error, error) {
	return durablefile.Lock(ctx, path)
}

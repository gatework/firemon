// Package device defines transport-independent configuration capture contracts.
package device

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

type View uint8

const (
	Running View = iota + 1
	Saved
)

type Capture struct {
	Source   config.Source
	Metadata fm.Metadata
}

// Reader owns its transport resources until Close, including after Read fails.
type Reader interface {
	Read(context.Context, View) (Capture, error)
	Close() error
}

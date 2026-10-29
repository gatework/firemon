package netconnector_test

import (
	"context"
	"errors"
	"testing"

	adapter "github.com/gatework/firemon/adapter/netconnector"
	"github.com/gatework/firemon/device"
)

func TestCanceledAdapterCallsPrecedeValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &adapter.Session{}
	checks := []struct {
		name string
		run  func() error
	}{
		{"read", func() error { _, err := s.Read(ctx, device.View(0)); return err }},
		{"execute", func() error { _, err := s.Execute(ctx, nil, nil); return err }},
		{"save", func() error { _, err := s.Save(ctx, nil); return err }},
		{"begin", func() error { return s.BeginConfiguration(ctx, "") }},
		{"end", func() error { return s.EndConfiguration(ctx, "") }},
		{"open", func() error { _, err := (adapter.Factory{}).Open(ctx, ""); return err }},
		{"open reader", func() error { _, err := (adapter.Factory{}).OpenReadOnly(ctx, ""); return err }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(); !errors.Is(err, context.Canceled) {
				t.Fatal("validation preceded cancellation", err)
			}
		})
	}
}

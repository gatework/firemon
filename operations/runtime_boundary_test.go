package operations_test

import (
	"context"
	"errors"
	"testing"

	"github.com/gatework/firemon/operations"
)

func TestRuntimeNilAndZeroBoundaries(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, receiver := range []struct {
		name    string
		runtime *operations.Runtime
	}{
		{name: "nil"}, {name: "zero", runtime: &operations.Runtime{}},
	} {
		for _, call := range []struct {
			name string
			run  func(context.Context) error
		}{
			{"collect", func(ctx context.Context) error {
				_, err := receiver.runtime.Collect(ctx, operations.CollectRequest{})
				return err
			}},
			{"design", func(ctx context.Context) error { _, err := receiver.runtime.Design(ctx, "", nil); return err }},
			{"apply", func(ctx context.Context) error { _, err := receiver.runtime.Apply(ctx, "", "", nil); return err }},
			{"recover", func(ctx context.Context) error { _, err := receiver.runtime.Recover(ctx, "", nil); return err }},
		} {
			for _, request := range []struct {
				name string
				ctx  context.Context
				want error
			}{
				{"background", context.Background(), operations.ErrInvalid},
				{"canceled", canceled, context.Canceled},
			} {
				t.Run(receiver.name+"/"+call.name+"/"+request.name, func(t *testing.T) {
					defer func() {
						if panicValue := recover(); panicValue != nil {
							t.Errorf("runtime boundary panicked: %v", panicValue)
						}
					}()
					if err := call.run(request.ctx); !errors.Is(err, request.want) {
						t.Fatalf("got %v, want %v", err, request.want)
					}
				})
			}
		}
	}
}

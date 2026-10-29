package operations_test

import (
	"context"
	"testing"

	"github.com/gatework/firemon/device"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/policy"
)

type configuredCollector struct {
	operations.CollectorOptions
	t *testing.T
}

func (c configuredCollector) Collect(ctx context.Context, r operations.CollectRequest) (operations.CollectResult, error) {
	c.t.Helper()
	v, err := operations.NewCollector(c.CollectorOptions)
	if err != nil {
		c.t.Fatal(err)
	}
	return v.Collect(ctx, r)
}

type mustDesigner struct {
	operations.DesignerOptions
	t *testing.T
}

func (d mustDesigner) Design(ctx context.Context, id string, r []policy.Request) (operations.DesignResult, error) {
	d.t.Helper()
	v, err := operations.NewDesigner(d.DesignerOptions)
	if err != nil {
		d.t.Fatal(err)
	}
	return v.Design(ctx, id, r)
}
func (d *nativeDevice) OpenReadOnly(ctx context.Context, id string) (device.Reader, error) {
	return d.Open(ctx, id)
}

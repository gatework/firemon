package netconnector_test

import (
	"context"
	"testing"

	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/plan"
)

type configuredEngine struct {
	deploy.Options
	t *testing.T
}

func (e configuredEngine) Apply(ctx context.Context, op, expected string, p *plan.Plan) (deploy.Result, error) {
	e.t.Helper()
	v, err := deploy.New(e.Options)
	if err != nil {
		e.t.Fatal(err)
	}
	return v.Apply(ctx, op, expected, p)
}
func (e configuredEngine) Recover(ctx context.Context, op string, p *plan.Plan) (deploy.Result, error) {
	e.t.Helper()
	v, err := deploy.New(e.Options)
	if err != nil {
		e.t.Fatal(err)
	}
	return v.Recover(ctx, op, p)
}

type configuredCollector struct {
	Options operations.CollectorOptions
	t       *testing.T
}

func (c configuredCollector) Collect(ctx context.Context, r operations.CollectRequest) (operations.CollectResult, error) {
	c.t.Helper()
	v, err := operations.NewCollector(c.Options)
	if err != nil {
		c.t.Fatal(err)
	}
	return v.Collect(ctx, r)
}

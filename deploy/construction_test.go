package deploy_test

import (
	"context"
	"testing"

	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/plan"
)

// Fixtures mutate options, then exercise only the public constructor and methods.
type configuredEngine struct {
	deploy.Options
	t *testing.T
}

func (e configuredEngine) engine() *deploy.Engine {
	e.t.Helper()
	v, err := deploy.New(e.Options)
	if err != nil {
		e.t.Fatal(err)
	}
	return v
}
func (e configuredEngine) Apply(ctx context.Context, op, expected string, p *plan.Plan) (deploy.Result, error) {
	return e.engine().Apply(ctx, op, expected, p)
}
func (e configuredEngine) Recover(ctx context.Context, op string, p *plan.Plan) (deploy.Result, error) {
	return e.engine().Recover(ctx, op, p)
}

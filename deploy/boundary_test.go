package deploy_test

import (
	"context"
	"errors"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/snapshot"
)

type brokenJournal struct{ lease deploy.Lease }

func (j *brokenJournal) Acquire(context.Context, string) (deploy.Lease, error) { return j.lease, nil }

type nilCurrent struct{ deploy.Repository }

func (s nilCurrent) Current(context.Context, string) (*fm.Firewall, snapshot.Head, error) {
	return nil, snapshot.Head{}, nil
}

type brokenFactory struct {
	session deploy.Session
	calls   int
}

func (f *brokenFactory) Open(context.Context, string) (deploy.Session, error) {
	f.calls++
	return f.session, nil
}
func TestDeploymentBrokenProvidersAndConstructorValidation(t *testing.T) {
	for _, kind := range []string{"nil lease", "typed nil lease", "nil current", "nil session", "typed nil session"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			switch kind {
			case "nil lease":
				f.engine.Journal = &brokenJournal{}
			case "typed nil lease":
				var lease *nilLease
				f.engine.Journal = &brokenJournal{lease: lease}
			case "nil current":
				f.engine.Store = nilCurrent{Repository: f.store}
			case "nil session":
				f.engine.Sessions = &brokenFactory{}
			case "typed nil session":
				var session *fakeSession
				f.engine.Sessions = &brokenFactory{session: session}
			}
			_, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan)
			if !errors.Is(err, deploy.ErrInvalid) {
				t.Fatal("broken provider accepted", err)
			}
			if f.device.executes != 0 || f.device.saves != 0 {
				t.Fatal("broken provider reached writes")
			}
			if kind == "nil session" || kind == "typed nil session" {
				if _, err := f.engine.Apply(context.Background(), "op", f.expected, f.plan); !errors.Is(err, deploy.ErrPending) {
					t.Fatal("uncertain operation retried", err)
				}
			}
		})
	}
	f := newFixture(t)
	var j *brokenJournal
	options := f.engine.Options
	options.Journal = j
	if _, err := deploy.New(options); !errors.Is(err, deploy.ErrInvalid) {
		t.Fatal("typed nil journal accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (deploy.Engine{}).Apply(ctx, "", "", nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation did not precede validation", err)
	}
	if _, err := (deploy.Engine{}).Recover(ctx, "", nil); !errors.Is(err, context.Canceled) {
		t.Fatal("recovery cancellation did not precede validation", err)
	}
}

type nilLease struct{ deploy.Lease }

func TestDeploymentConstructorRejectsEachTypedNilDependency(t *testing.T) {
	f := newFixture(t)
	var nilRepo *nilCurrent
	var nilJournal *brokenJournal
	var nilFactory *brokenFactory
	var nilParser *fakeDevice
	var nilAuthorize deploy.AuthorizeFunc
	for _, field := range []string{"repository", "journal", "factory", "parser", "authorizer", "timeout"} {
		t.Run(field, func(t *testing.T) {
			options := f.engine.Options
			switch field {
			case "repository":
				options.Store = nilRepo
			case "journal":
				options.Journal = nilJournal
			case "factory":
				options.Sessions = nilFactory
			case "parser":
				options.Parser = nilParser
			case "authorizer":
				options.Authorizer = nilAuthorize
			case "timeout":
				options.Timeout = -1
			}
			if _, err := deploy.New(options); !errors.Is(err, deploy.ErrInvalid) {
				t.Fatal("invalid constructor dependency accepted", err)
			}
		})
	}
}

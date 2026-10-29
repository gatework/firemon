package operations

import (
	"time"

	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors"
)

// Options contains host-owned dependencies. Store is normally a snapshot.Store;
// sessions resolve host inventory and credentials, and Authorizer decides whether
// the exact operation and plan may be applied. No device is opened by New.
type Options struct {
	Store         deploy.Repository
	Journal       deploy.Journal
	Sessions      deploy.Factory
	Authorizer    deploy.Authorizer
	Policy        policy.Engine
	Timeout       time.Duration
	MaxCandidates int
}

// Runtime wires the native capture and design boundary to the existing durable
// deployment engine. Apply and Recover remain methods of Deployment. Hosts use
// their Store directly to load graphs for the policy and analysis packages.
type Runtime struct {
	Collector  Collector
	Designer   Designer
	Deployment deploy.Engine
}

func New(options Options) (*Runtime, error) {
	if options.Store == nil || options.Journal == nil || options.Sessions == nil || options.Authorizer == nil {
		return nil, ErrInvalid
	}
	if authorize, ok := options.Authorizer.(deploy.AuthorizeFunc); ok && authorize == nil {
		return nil, ErrInvalid
	}
	parser := vendors.Parser{}
	return &Runtime{
		Collector: Collector{Store: options.Store, Sessions: options.Sessions, Parser: parser, Timeout: options.Timeout},
		Designer:  Designer{Store: options.Store, Engine: options.Policy, MaxCandidates: options.MaxCandidates, Timeout: options.Timeout},
		Deployment: deploy.Engine{Store: options.Store, Journal: options.Journal, Sessions: options.Sessions,
			Parser: parser, Authorizer: options.Authorizer, Timeout: options.Timeout},
	}, nil
}

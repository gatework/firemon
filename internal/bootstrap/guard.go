package bootstrap

import (
	"context"
	"fmt"
	"time"

	"github.com/gatework/netops/authz"
	nbootstrap "github.com/gatework/netops/bootstrap"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/lease"
	filelease "github.com/gatework/netops/store/lease"

	"github.com/gatework/firemon/deploy"
)

// Guard builds the protection of a deployment: device leases in the area
// every gatework tool shares (so firemon and fabric never change one device
// at once) and, when authzPath names a policy, the deploy permission of
// $USER. getenv reads the process environment.
func Guard(ctx context.Context, getenv func(string) string, authzPath string, ttl time.Duration) (deploy.Guard, error) {
	home := getenv("HOME")
	env := nbootstrap.Env{App: "firemon", Home: home, Environ: map[string]string{"GATEWORK_LEASES_DIR": getenv("GATEWORK_LEASES_DIR")}}
	dir := env.SharedDir(nbootstrap.LeaseArea)
	if dir == "" {
		return deploy.Guard{}, fmt.Errorf("bootstrap: no home directory for the shared lease area")
	}
	st, err := filelease.Open(dir)
	if err != nil {
		return deploy.Guard{}, fmt.Errorf("bootstrap: leases: %w", err)
	}
	actor := getenv("USER")
	g := deploy.Guard{Leases: lease.NewManager(st, nil), Holder: lease.Holder{Tool: "firemon", Actor: actor}, LeaseTTL: ttl}
	if authzPath == "" {
		return g, nil
	}
	body, _, err := nbootstrap.ReadFile(ctx, authzPath, false)
	if err != nil {
		return deploy.Guard{}, fmt.Errorf("bootstrap: authz %s: %w", authzPath, err)
	}
	policy, err := authz.Decode(body)
	if err != nil {
		return deploy.Guard{}, fmt.Errorf("bootstrap: authz %s: %w", authzPath, err)
	}
	g.Authorize = func(d device.Device) error { return policy.Authorize(actor, authz.PermDeploy, d) }
	return g, nil
}

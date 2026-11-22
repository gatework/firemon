package deploy_test

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/netops/authz"
	ndevice "github.com/gatework/netops/device"
	"github.com/gatework/netops/failure"
	"github.com/gatework/netops/lease"
	filelease "github.com/gatework/netops/store/lease"

	"github.com/gatework/firemon/deploy"
)

func TestDeployer_Guard(t *testing.T) {
	t.Parallel()
	text := fixture(t)
	p, commands := planFor(t, text)
	fw := ndevice.Device{ID: "fw1", Mgmt: netip.MustParseAddr("192.0.2.1"), Platform: "hillstone", Site: "dc1"}
	st, err := filelease.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leases := lease.NewManager(st, nil)
	policy, _ := authz.Decode([]byte("roles: [{name: fw, permissions: [deploy], scope: ['site=dc2']}]\nbindings: {alice: [fw]}\n"))

	dev := &device{text: text}
	d := deploy.New(dev.open, deploy.Options{Writer: fixed(commands), Journal: &journal{}, Now: func() time.Time { return now },
		Guard: deploy.Guard{Authorize: func(d ndevice.Device) error { return policy.Authorize("alice", authz.PermDeploy, d) }}})
	if _, err := d.Deploy(t.Context(), deploy.Request{Plan: p, Device: fw}); !errors.Is(err, deploy.ErrUnauthorized) || len(dev.writes) != 0 {
		t.Fatalf("unauthorized deploy: %v, %d writes", err, len(dev.writes))
	}

	held, err := leases.Acquire(t.Context(), []string{lease.Key(fw)}, lease.Holder{Tool: "fabric", Actor: "bob"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	guard := deploy.Guard{Leases: leases, Holder: lease.Holder{Actor: "alice"}}
	d = deploy.New(dev.open, deploy.Options{Writer: fixed(commands), Journal: &journal{}, Now: func() time.Time { return now }, Guard: guard})
	receipt, err := d.Deploy(t.Context(), deploy.Request{Plan: p, Device: fw})
	if !errors.Is(err, lease.ErrHeld) || receipt.Record.Failure != failure.CodeBusy || len(dev.writes) != 0 {
		t.Fatalf("leased device: %v %+v", err, receipt.Record)
	}
	_ = leases.Release(t.Context(), held)
	if _, err := d.Deploy(t.Context(), deploy.Request{Plan: p, Device: fw}); err != nil {
		t.Fatalf("deploy after release: %v", err)
	}
	if hs, _ := leases.Holders(t.Context(), []string{lease.Key(fw)}); len(hs) != 0 {
		t.Errorf("lease left behind: %+v", hs)
	}
}

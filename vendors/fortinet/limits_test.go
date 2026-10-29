package fortinet_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/fortinet"
)

func TestFortinetCancellationAndCumulativeNATBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fortinet.Parse(ctx, config.Source{Text: fixture(t, "basic"), Complete: true}, fm.Metadata{Device: "synthetic"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	fw := parse(t, fixture(t, "basic")+nativeNAT)
	q := policy.Request{Scope: "root", FromZone: "wan1", ToZone: "inside", Traffic: traffic(t, "203.0.113.5/32", "198.51.100.20/32", 6, 1000, 443)}
	if _, err := (policy.Engine{}).QueryPacket(ctx, fw, policy.PacketRequest{Request: q}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := (policy.Engine{Limits: policy.Limits{Rules: 2}}).QueryNAT(context.Background(), fw, q); !errors.Is(err, policy.ErrBudget) {
		t.Fatal(err)
	}
}

func TestFortinetScopeCannotBeInferredAcrossExplicitVDOMBoundaries(t *testing.T) {
	raw := "config vdom\nedit blue\nnext\nend\nconfig firewall address\nedit outside\nset subnet 192.0.2.1 255.255.255.255\nnext\nend\n"
	fw, err := fortinet.ParseVDOM(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "synthetic"}, "blue")
	if err != nil {
		t.Fatal(err)
	}
	if fw.Address("outside") != nil || fw.Complete() {
		t.Fatal("root object was assumed to belong to selected VDOM")
	}
	raw = "config vdom\nedit blue\nconfig system interface\nedit port1\nset ip 192.0.2.1 255.255.255.0\nnext\nend\nnext\nend\n"
	fw, err = fortinet.ParseVDOM(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "synthetic"}, "blue")
	if err != nil || fw.Interface("port1") == nil || fw.Interface("port1").Scope() != "blue" {
		t.Fatal("local interface context", err)
	}
	fw, err = fortinet.ParseVDOM(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "synthetic"}, "absent")
	if err != nil {
		t.Fatal(err)
	}
	if fw.Complete() {
		t.Fatal("missing selected VDOM looked like complete empty configuration")
	}
}

func TestFortinetUnconfiguredInterfaceCannotCreateDefaultConnectedRoute(t *testing.T) {
	fw := parse(t, "config system interface\nedit empty\nset ip 0.0.0.0 0.0.0.0\nnext\nend\n")
	if !fw.Complete() || len(fw.Routes()) != 0 || len(fw.Interface("empty").Record().Addresses) != 0 {
		t.Fatal(fw.Export(), fw.Diagnostics())
	}
}

func TestFortinetUnknownSourceForcingCannotFallThroughToPool(t *testing.T) {
	raw := strings.Replace(fixture(t, "basic")+nativeNAT, "set portforward enable", "set portforward enable\nset nat-source-vip enable", 1)
	fw := parse(t, raw)
	got, err := (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{Scope: "root", FromZone: "inside", ToZone: "wan1", Traffic: traffic(t, "192.0.2.21/32", "203.0.113.50/32", 6, 22, 443)})
	if err != nil || got.Unknown.Empty() || len(got.Relations) != 0 {
		t.Fatal("unmodeled port-forward source selection became pool NAT", got, err)
	}
}

func TestFortinetRendererRejectsInvalidCreationIDsWithoutPanicking(t *testing.T) {
	fw := parse(t, fixture(t, "basic"))
	_, err := (fortinet.Renderer{}).Render(context.Background(), fw, fw, []plan.Change{{Kind: plan.CreateRule, Rule: "missing1"}, {Kind: plan.CreateRule, Rule: "missing2"}})
	if err == nil {
		t.Fatal("invalid creation accepted")
	}
}

func FuzzScopedCapture(f *testing.F) {
	f.Add("config firewall address\nedit x\nset subnet 192.0.2.1 255.255.255.255\nnext\nend\n")
	f.Add("config unsupported\nconfig firewall address\nedit x\nset subnet 192.0.2.1 255.255.255.255\nnext\nend\nend\n")
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 1<<16 {
			t.Skip()
		}
		fw, err := fortinet.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "synthetic"})
		if err != nil {
			return
		}
		if fw.Metadata().Vendor != "fortinet" || fw.Metadata().Context != "root" {
			t.Fatal("context lost")
		}
		again, err := fm.Seal(fw.Export())
		if err != nil || again.SemanticDigest() != fw.SemanticDigest() {
			t.Fatal("nondeterministic graph", err)
		}
	})
}

package netscreen_test

import (
	"context"
	"errors"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/netscreen"
)

func TestNATAndPacketShareBudgetsAndRespectCancellation(t *testing.T) {
	fw := parse(t, fixture(t, "nat"))
	q := policy.Request{Traffic: traffic(t, "203.0.113.5/32", "198.51.100.70/32", 6, 12345, 8443), FromZone: "Untrust", ToZone: "Trust"}
	e := policy.Engine{Limits: policy.Limits{Rules: 1}}
	if _, err := e.QueryNAT(context.Background(), fw, q); !errors.Is(err, policy.ErrBudget) {
		t.Fatal(err)
	}
	if _, err := e.QueryPacket(context.Background(), fw, policy.PacketRequest{Request: q}); !errors.Is(err, policy.ErrBudget) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := netscreen.Parse(ctx, config.Source{Text: fixture(t, "nat"), Complete: true}, fm.Metadata{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := e.QueryPacket(ctx, fw, policy.PacketRequest{Request: q}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func FuzzScopedCapture(f *testing.F) {
	f.Add("set interface ethernet0/1 zone Trust\nset interface ethernet0/1 ip 192.0.2.1/24\n")
	f.Add("set vrouter vr\nset route 203.0.113.0/24 gateway 192.0.2.1\nexit\n")
	f.Add("set policy id 1 from Trust to Untrust Any Any ANY nat src dip-id 4 permit\nexit\n")
	f.Add("set vsys opaque\nset address Trust nested 192.0.2.1/32\nexit\n")
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 8192 {
			t.Skip()
		}
		fw, err := netscreen.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "fuzz"})
		if err != nil {
			return
		}
		if fw == nil {
			t.Fatal("nil graph without error")
		}
		for _, r := range fw.Export().Evidence {
			if r.Span.First < 1 || r.Span.Last < r.Span.First {
				t.Fatal(r)
			}
		}
	})
}

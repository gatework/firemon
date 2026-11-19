package oracle_test

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/internal/oracle"
	"github.com/gatework/firemon/traffic"
	"github.com/gatework/firemon/vendors/hillstone"
	"github.com/gatework/firemon/vendors/paloalto"
)

// blockLoop blocks one host and port on a firewall and proves the change
// with the oracle: the blocked packets are denied between every pair of
// zones, every other boundary packet decides as before, and the commands
// read back to the prediction.
func blockLoop(t *testing.T, d device, host netip.Addr, port uint16) []string {
	t.Helper()
	svc := traffic.NewService(traffic.ProtocolTCP, traffic.AnyPort, traffic.Port(port))
	in := design.Intent{Src: traffic.AnyAddress(), Dst: traffic.NewAddressSet(netip.PrefixFrom(host, host.BitLen())), Service: svc}
	caps := paloalto.Capabilities()
	if d.fw.Config().Vendor == firemon.VendorHillstone {
		caps = hillstone.Capabilities()
	}
	bp, err := design.New(d.fw, design.Options{Now: func() time.Time { return at }, Capabilities: caps}).PlanBlock(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(bp.Changes) == 0 {
		return nil // already blocked
	}
	if !bp.Verified {
		return []string{"block not verified: " + bp.VerifyError}
	}
	predicted := d.fw.Config()
	if err := design.Apply(predicted, bp.Changes); err != nil {
		t.Fatal(err)
	}
	after, err := firemon.Compile(predicted)
	if err != nil {
		t.Fatal(err)
	}
	var failures []string
	zones := zoneNames(d.fw)
	blockedPacket := oracle.Packet{Src: netip.MustParseAddr("192.0.2.1"), Dst: host, Protocol: traffic.ProtocolTCP, SrcPort: 40000, DstPort: port}
	for _, from := range zones {
		for _, to := range zones {
			p := blockedPacket
			p.From, p.To = from, to
			if v := oracle.Decide(after, p, at); v.Action() == firemon.ActionPermit || !v.Settled() {
				failures = append(failures, fmt.Sprintf("%v still not denied (rule %s)", p, name(v.Rule)))
			}
		}
	}
	blocked := traffic.Space{Src: traffic.AnyAddress(), Dst: in.Dst, Service: svc}
	for _, r := range d.fw.Rules() {
		if r.Ignored() {
			continue
		}
		for _, p := range boundaryPackets(r, zones) {
			if blocked.Src.Contains(p.Src) && blocked.Dst.Contains(p.Dst) && blocked.Service.ContainsSet(p.Service()) {
				continue
			}
			before, now := oracle.Decide(d.fw, p, at), oracle.Decide(after, p, at)
			if before.Action() != now.Action() || before.Settled() != now.Settled() {
				failures = append(failures, fmt.Sprintf("%v changed from %s to %s", p, before.Action(), now.Action()))
			}
		}
	}
	script, err := d.render(bp.Plan)
	if err != nil {
		t.Fatal(err)
	}
	back, err := d.readback(script.Commands)
	if err != nil {
		t.Fatal(err)
	}
	if same, err := sameObjects(back, predicted); err != nil || !same {
		failures = append(failures, fmt.Sprintf("readback differs from the prediction (%v)", err))
	}
	return failures
}

func TestBlockLoop_Fixtures(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		filepath.Join("..", "..", "vendors", "hillstone", "testdata", "basic.conf"),
		filepath.Join("..", "..", "vendors", "paloalto", "testdata", "basic.conf"),
	} {
		d, ok := loadDevice(t, path)
		if !ok {
			t.Fatal("fixture not recognised")
		}
		for _, f := range blockLoop(t, d, netip.MustParseAddr("172.16.0.10"), 443) {
			t.Error(f)
		}
	}
}

// TestBlockLoop_Corpus blocks a host and port on every configuration of
// the private corpus; it prints counts only (TST-3).
func TestBlockLoop_Corpus(t *testing.T) {
	t.Parallel()
	dir := os.Getenv("FIREMON_CORPUS")
	if dir == "" {
		t.Skip("FIREMON_CORPUS not set")
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			d, ok := loadDevice(t, path)
			if !ok {
				t.Skip("not a firewall configuration")
			}
			failures := blockLoop(t, d, netip.MustParseAddr("203.0.113.66"), 445)
			t.Logf("block failures=%d", len(failures))
			for _, f := range failures[:min(len(failures), 10)] {
				t.Error(f)
			}
		})
	}
}

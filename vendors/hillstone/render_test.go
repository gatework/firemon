package hillstone_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
	"github.com/gatework/firemon/vendors/hillstone"
)

func designFixture(t *testing.T, src, dst, svc string) (*design.Plan, design.Script) {
	t.Helper()
	fw, err := firemon.Compile(parseFixture(t, "basic.conf"))
	if err != nil {
		t.Fatal(err)
	}
	in := design.Intent{Name: "req-42", Description: "ticket 42"}
	in.Src, _ = traffic.ParseAddressSet(src)
	in.Dst, _ = traffic.ParseAddressSet(dst)
	in.Service, _ = traffic.ParseServiceSet(svc)
	p, err := design.New(fw, design.Options{Now: func() time.Time { return time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC) }}).Plan(in)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Verified || p.Status != design.StatusChange {
		t.Fatalf("plan %s verified=%v unknown=%v", p.Status, p.Verified, p.Unknown)
	}
	script, err := hillstone.Renderer{}.Render(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, script
}

func TestRenderer_Golden(t *testing.T) {
	t.Parallel()
	_, script := designFixture(t, "10.0.5.0/24", "172.16.0.40-172.16.0.41", "tcp/8443,udp/53")
	got := "# commands\n" + strings.Join(script.Commands, "\n") + "\n# rollback\n" + strings.Join(script.Rollback, "\n") + "\n"
	golden := filepath.Join("testdata", "render.golden")
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(string(want), got); diff != "" {
		t.Fatalf("golden mismatch (-want +got), rerun with -update:\n%s", diff)
	}
}

// TestRenderer_RoundTrip appends the rendered blocks to the configuration
// and checks that the device would then permit the intent.
func TestRenderer_RoundTrip(t *testing.T) {
	t.Parallel()
	p, script := designFixture(t, "10.0.5.0/24", "172.16.0.40-172.16.0.41", "tcp/8443")
	raw, err := os.ReadFile(filepath.Join("testdata", "basic.conf"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw) + strings.Join(script.Commands, "\n") + "\n"
	cfg, err := hillstone.New(hillstone.Options{}).Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := query.New(fw, query.Options{}).Query(query.Request{Src: p.Intent.Src, Dst: p.Intent.Dst, Service: p.Intent.Service})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != query.VerdictAllowed {
		t.Fatalf("after rendering: %s", res.Verdict)
	}
}

func TestRenderer_IPv6Range(t *testing.T) {
	t.Parallel()
	p := &design.Plan{Changes: []design.Change{design.AddAddress{Address: firemon.Address{Name: "v6r", Entries: []firemon.AddressEntry{
		firemon.RangeEntry(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::9")),
	}}}}}
	s, err := hillstone.Renderer{}.Render(p)
	if err != nil || s.Commands[0] != `address "v6r" ipv6` {
		t.Fatalf("got %v %v", s.Commands, err)
	}
}

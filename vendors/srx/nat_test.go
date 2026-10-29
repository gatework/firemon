package srx_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func natFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/nat.set")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestNativeNATCatalogsAndPostDestinationSourceSelection(t *testing.T) {
	fw := parse(t, natFixture(t))
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	if len(fw.StaticNATs()) != 2 || len(fw.DynamicNATs()) != 4 || len(fw.NATPools()) != 2 {
		t.Fatal("NAT catalogs collapsed")
	}
	// The same native name is legal in independent source/destination pools.
	if fw.NATPools()[0].ID() == fw.NATPools()[1].ID() {
		t.Fatal("pool namespaces collapsed")
	}
	for _, tc := range []struct {
		src, dst, from, to, wsrc, wdst string
		sp, dp, wsp, wdp               uint16
		possible                       bool
		steps                          int
	}{
		{"198.51.100.50", "198.51.100.130", "outside", "inside", "198.51.100.200", "192.0.2.130", 12345, 443, 40000, 443, true, 2},
		{"192.0.2.130", "198.51.100.50", "inside", "outside", "198.51.100.130", "198.51.100.50", 12345, 443, 12345, 443, false, 1},
		{"198.51.100.50", "198.51.100.80", "outside", "inside", "198.51.100.200", "192.0.2.80", 12345, 8080, 40000, 80, true, 2},
		{"192.0.2.90", "198.51.100.50", "inside", "outside", "198.51.100.90", "198.51.100.50", 2001, 443, 1001, 443, false, 1},
		{"192.0.2.10", "198.51.100.50", "inside", "outside", "192.0.2.10", "198.51.100.50", 12345, 443, 12345, 443, false, 1},
	} {
		q := policy.Request{Traffic: traffic(t, tc.src+"/32", tc.dst+"/32", 6, tc.sp, tc.dp), FromZone: fm.ID(tc.from), ToZone: fm.ID(tc.to)}
		r, err := (policy.Engine{}).QueryNAT(context.Background(), fw, q)
		if err != nil || !r.Complete || len(r.Relations) != 1 || !r.Unmatched.Empty() || !r.Unknown.Empty() {
			t.Fatal(tc, r, err)
		}
		rel := r.Relations[0]
		b := rel.Translated.Regions()
		if len(b) != 1 || b[0].Source.First != netip.MustParseAddr(tc.wsrc) || b[0].Destination.First != netip.MustParseAddr(tc.wdst) || b[0].SourcePort.Low != tc.wsp || b[0].DestinationPort.Low != tc.wdp || rel.PossibleAllocation != tc.possible || rel.Exact == tc.possible || len(rel.Steps) != tc.steps {
			t.Fatal(tc, rel, b)
		}
		missing, _ := q.Traffic.Difference(rel.Original, 16)
		extra, _ := rel.Original.Difference(q.Traffic, 16)
		if !missing.Empty() || !extra.Empty() {
			t.Fatal("lost original pair")
		}
		if tc.possible && b[0].SourcePort.High != 40010 {
			t.Fatal("ignored pool port range", b)
		}
	}
}

func TestNATUnsupportedContextsAndPoolModesStayUnknown(t *testing.T) {
	for _, extra := range []string{
		"set security nat source pool shared address-persistent\n",
		"set security nat source rule-set specific from interface ge-0/0/0.0\nset security nat source rule-set specific to zone outside\nset security nat source rule-set specific rule hide match source-address 192.0.2.0/24\nset security nat source rule-set specific rule hide then source-nat off\n",
		"deactivate security nat source rule-set outbound rule hide match source-address\n",
		"set security nat destination pool shared routing-instance customer\n",
	} {
		fw := parse(t, natFixture(t)+extra)
		if fw.Complete() {
			t.Fatal("unsupported NAT accepted", extra)
		}
		r, err := (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{Traffic: traffic(t, "192.0.2.20/32", "198.51.100.50/32", 6, 12345, 443), FromZone: "inside", ToZone: "outside"})
		if err != nil || r.Complete || len(r.Relations) != 0 || r.Unknown.Empty() {
			t.Fatal(extra, r, err)
		}
	}
}

func TestSourceNATWithoutPATPreservesPortAndDeactivatedRuleIsSkipped(t *testing.T) {
	raw := strings.ReplaceAll(natFixture(t), "port range 40000 to 40010", "port no-translation")
	fw := parse(t, raw+"deactivate security nat source rule-set outbound rule exempt\n")
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	r, err := (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{Traffic: traffic(t, "192.0.2.10/32", "198.51.100.50/32", 6, 12345, 443), FromZone: "inside", ToZone: "outside"})
	if err != nil || len(r.Relations) != 1 || r.Relations[0].Translated.Regions()[0].SourcePort != (flow.Interval{Low: 12345, High: 12345}) || !r.Relations[0].PossibleAllocation {
		t.Fatal(r, err)
	}
}

func TestSRXPacketUsesRealDestinationAndServiceBeforeSourceNAT(t *testing.T) {
	for _, permit := range []bool{true, false} {
		raw := natFixture(t)
		if !permit {
			raw = strings.ReplaceAll(raw, "web then permit", "web then deny")
		}
		fw := parse(t, raw)
		q := policy.PacketRequest{Request: policy.Request{Traffic: traffic(t, "198.51.100.50/32", "198.51.100.80/32", 6, 12345, 8080), FromZone: "outside"}}
		r, err := (policy.Engine{}).QueryPacket(context.Background(), fw, q)
		if err != nil || !r.Complete || !r.Unknown.Empty() || len(r.Paths) != 1 {
			t.Fatal(r, err)
		}
		p := r.Paths[0]
		if p.ToZone != "inside" || p.Policy.Allowed.Empty() == permit || p.Policy.Denied.Empty() != permit {
			t.Fatal(p)
		}
		coverage := p.Policy.Allowed
		if !permit {
			coverage = p.Policy.Denied
		}
		b := coverage.Regions()
		if len(b) != 1 || b[0].Source.First.String() != "198.51.100.50" || b[0].Destination.First.String() != "192.0.2.80" || b[0].DestinationPort.Low != 80 {
			t.Fatal("wrong native policy view", b)
		}
		if permit && len(p.NAT.Steps) != 2 || !permit && len(p.NAT.Steps) != 1 {
			t.Fatal("SNAT must follow policy acceptance", p.NAT)
		}
	}
}

func TestSRXNATPreservesPairsAndChargesCumulativeBudget(t *testing.T) {
	fw := parse(t, natFixture(t))
	a := traffic(t, "192.0.2.90/32", "198.51.100.50/32", 6, 2001, 443)
	b := traffic(t, "192.0.2.10/32", "198.51.100.60/32", 17, 1234, 53)
	paired, err := a.Union(b, 16)
	if err != nil {
		t.Fatal(err)
	}
	q := policy.Request{Traffic: paired, FromZone: "inside", ToZone: "outside"}
	r, err := (policy.Engine{}).QueryNAT(context.Background(), fw, q)
	if err != nil || !r.Complete || len(r.Relations) != 2 {
		t.Fatal(r, err)
	}
	var actual flow.Traffic
	for _, rel := range r.Relations {
		actual, err = actual.Union(rel.Translated, 16)
		if err != nil {
			t.Fatal(err)
		}
	}
	want, err := traffic(t, "198.51.100.90/32", "198.51.100.50/32", 6, 1001, 443).Union(b, 16)
	if err != nil {
		t.Fatal(err)
	}
	extra, _ := actual.Difference(want, 16)
	missing, _ := want.Difference(actual, 16)
	if !extra.Empty() || !missing.Empty() {
		t.Fatal("invented cross pairs", actual)
	}
	_, err = (policy.Engine{Limits: policy.Limits{MaxVisits: 1}}).QueryNAT(context.Background(), fw, q)
	if !errors.Is(err, policy.ErrBudget) {
		t.Fatal(err)
	}
}

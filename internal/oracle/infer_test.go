package oracle_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// TestInference_Corpus checks that application identification by standard
// ports and the user, URL and schedule premises refine the strict reading
// (ADR 0017): where strict evaluation decides, inference gives the same
// verdict, and it never leaves undecided what strict evaluation decides.
// Probes take a host of each rule's source and destination on common
// services. Only aggregate counts are printed.
func TestInference_Corpus(t *testing.T) {
	t.Parallel()
	dir := os.Getenv("FIREMON_CORPUS")
	if dir == "" {
		t.Skip("FIREMON_CORPUS not set")
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	services := []string{"tcp/22", "tcp/443", "tcp/3389", "udp/53", "tcp/8080", "tcp/9600"}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			d, ok := loadDevice(t, path)
			if !ok {
				t.Skip("not a firewall configuration")
			}
			engine := query.New(d.fw, query.Options{Now: func() time.Time { return at }})
			var probes, strictUnknown, inferredUnknown int
			for _, r := range d.fw.Rules() {
				src, dst := firstHost(r.Match().Src), firstHost(r.Match().Dst)
				if src.IsEmpty() || dst.IsEmpty() {
					continue
				}
				for _, s := range services {
					svc, _ := traffic.ParseServiceSet(s)
					req := query.Request{Src: src, Dst: dst, Service: svc, At: at}
					inferred, err1 := engine.Query(req)
					req.Strict = true
					strict, err2 := engine.Query(req)
					if err1 != nil || err2 != nil || strict.Incomplete || inferred.Incomplete {
						continue
					}
					probes++
					if strict.Verdict == query.VerdictIndeterminate {
						strictUnknown++
					}
					if inferred.Verdict == query.VerdictIndeterminate {
						inferredUnknown++
					}
					if strict.Verdict != query.VerdictIndeterminate && inferred.Verdict != strict.Verdict {
						t.Errorf("rule %s %s: strict %s, inferred %s", r.ID(), s, strict.Verdict, inferred.Verdict)
					}
				}
			}
			if inferredUnknown > strictUnknown {
				t.Errorf("inference left more undecided: %d > %d", inferredUnknown, strictUnknown)
			}
			t.Logf("probes=%d indeterminate strict=%d inferred=%d", probes, strictUnknown, inferredUnknown)
		})
	}
}

// firstHost is the first address of a set as a host, or empty.
func firstHost(s traffic.AddressSet) traffic.AddressSet {
	rs := s.Ranges()
	if len(rs) == 0 {
		return traffic.AddressSet{}
	}
	a := rs[0].From()
	if a.IsUnspecified() {
		a = a.Next()
	}
	return traffic.NewAddressSet(netip.PrefixFrom(a, a.BitLen()))
}

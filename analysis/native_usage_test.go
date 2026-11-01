package analysis_test

import (
	"context"
	"errors"
	"fmt"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors"
	"os"
	"strings"
	"testing"
	"time"
)

func usageFixture(t *testing.T, vendor string) *fm.Firewall {
	t.Helper()
	raw, e := os.ReadFile("../vendors/testdata/perl/" + vendor + ".cfg")
	if e != nil {
		t.Fatal(e)
	}
	if vendor == "netscreen" {
		raw = append(raw, []byte("set zone inside block\n")...)
	}
	fw, e := (vendors.Parser{}).Parse(t.Context(), config.Source{Text: string(raw), Complete: true}, fm.Metadata{Device: "synthetic-usage", Vendor: vendor, Software: "9.16"})
	if e != nil || !fw.Complete() {
		t.Fatal(fw, e)
	}
	return fw
}
func TestNativeSessionUsagePreservesPairsAndUnknown(t *testing.T) {
	at := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	for _, vendor := range []string{"srx", "netscreen"} {
		t.Run(vendor, func(t *testing.T) {
			fw := usageFixture(t, vendor)
			line := "2026-11-01T01:00:00Z fw RT_FLOW: session created 192.0.2.10/12345->192.0.2.10/443 a b c d 6 allow inside inside"
			if vendor == "netscreen" {
				line = "2026-11-01T01:00:00Z fw policy_id=1 session=123 proto=6 src=192.0.2.10 dst=192.0.2.10 src_port=12345 dst_port=443"
			}
			input := analysis.SessionLog{Revision: "rev", GraphDigest: fw.SemanticDigest(), Source: "synthetic", Window: fm.TimeWindow{Start: at.Add(-time.Hour), End: at.Add(time.Hour)}, Complete: true, Reader: strings.NewReader(line + "\n" + line + "\n")}
			got, e := (analysis.NativeUsage{}).ReadSessions(t.Context(), fw, "rev", input)
			if e != nil || len(got.Tuples) != 1 || len(got.Observations) != 1 || got.Observations[0].Hits != 1 || len(got.Members) == 0 {
				t.Fatal(got, e)
			}
			tuple := got.Tuples[0].Traffic
			if tuple.Source.First.String() != "192.0.2.10" || tuple.DestinationPort.Low != 443 || tuple.SourcePort.Low != 12345 {
				t.Fatal(tuple)
			}
			for _, bad := range []string{strings.TrimPrefix(line, "2026-11-01T01:00:00Z "), strings.Replace(line, "2026-11-01T01:00:00Z", "2026-11-01T01:00:00", 1), strings.Replace(line, "2026-11-01", "2026-10-01", 1), strings.Replace(line, "443", "999", 1), strings.Replace(line, "proto=6", "proto=47", 1)} {
				if bad == line {
					continue
				}
				input.Reader = strings.NewReader(bad)
				report, e := (analysis.NativeUsage{}).ReadSessions(t.Context(), fw, "rev", input)
				if e != nil || len(report.Observations) != 0 || report.Complete || len(report.Issues) == 0 {
					t.Fatal("invalid evidence became usage", report, e)
				}
			}
			input.Reader = strings.NewReader("")
			empty, e := (analysis.NativeUsage{}).ReadSessions(t.Context(), fw, "rev", input)
			if e != nil || len(empty.Observations) != 0 {
				t.Fatal("missing logs imply unused", empty, e)
			}
			input.Reader = strings.NewReader(line)
			input.Revision = "different"
			stale, e := (analysis.NativeUsage{}).ReadSessions(t.Context(), fw, "rev", input)
			if e != nil || len(stale.Observations) != 0 || stale.Complete {
				t.Fatal(stale, e)
			}
		})
	}
}
func TestASACounterDeltasRequireIdentityWindowAndEpoch(t *testing.T) {
	fw := usageFixture(t, "asa")
	at := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	sample := func(n uint64, line int, when time.Time) analysis.CounterSample {
		return analysis.CounterSample{At: when, Source: "synthetic", Revision: "rev", GraphDigest: fw.SemanticDigest(), Epoch: "verified-same-counter-generation", Complete: true, Reader: strings.NewReader(fmt.Sprintf("access-list inbound line %d extended permit tcp object-group hosts object-group hosts object-group apps (hitcnt=%d) 0x123\n", line, n))}
	}
	for _, tc := range []struct {
		name            string
		a, b            uint64
		epoch, revision string
		want            uint64
		complete        bool
	}{{"positive", 10, 13, "verified-same-counter-generation", "rev", 3, true}, {"zero", 10, 10, "verified-same-counter-generation", "rev", 0, true}, {"reset", 10, 2, "verified-same-counter-generation", "rev", 0, false}, {"epoch", 10, 13, "new", "rev", 0, false}, {"missing epoch", 10, 13, "", "rev", 0, false}, {"revision", 10, 13, "verified-same-counter-generation", "other", 0, false}} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := sample(tc.a, 1, at), sample(tc.b, 70, at.Add(time.Hour))
			b.Epoch, b.Revision = tc.epoch, tc.revision
			got, e := (analysis.NativeUsage{}).ReadASACounters(t.Context(), fw, "rev", a, b)
			if e != nil {
				t.Fatal(e)
			}
			if tc.complete {
				if len(got.Observations) != 1 || got.Observations[0].Hits != tc.want || !got.Observations[0].Complete {
					t.Fatal(got)
				}
			} else {
				for _, o := range got.Observations {
					if o.Hits != 0 || o.Complete {
						t.Fatal("uncertain delta became positive/unused", got)
					}
				}
			}
			if len(got.Members) != 0 || len(got.Tuples) != 0 {
				t.Fatal("aggregate count became members/tuples")
			}
		})
	}
	expanded := sample(1, 1, at)
	expanded.Reader = strings.NewReader("access-list inbound line 1 extended permit tcp host 192.0.2.10 host 192.0.2.10 eq 443 (hitcnt=1)\n")
	report, e := (analysis.NativeUsage{}).ReadASACounters(t.Context(), fw, "rev", expanded, sample(2, 1, at.Add(time.Hour)))
	if e != nil || report.Complete {
		t.Fatal(report, e)
	}
	for _, o := range report.Observations {
		if o.Hits != 0 || o.Complete {
			t.Fatal("expanded child bound to parent", report)
		}
	}
}
func TestNativeUsageBoundedStream(t *testing.T) {
	fw := usageFixture(t, "netscreen")
	at := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	in := analysis.SessionLog{Revision: "rev", GraphDigest: fw.SemanticDigest(), Source: "synthetic", Window: fm.TimeWindow{Start: at, End: at.Add(time.Hour)}, Reader: strings.NewReader(strings.Repeat("x", 1024))}
	r, e := (analysis.NativeUsage{MaxBytes: 32}).ReadSessions(t.Context(), fw, "rev", in)
	if !errors.Is(e, policy.ErrBudget) || r.Complete || len(r.Observations) != 0 {
		t.Fatal(r, e)
	}
	in.Reader = strings.NewReader(strings.Repeat("unknown\n", 100))
	r, e = (analysis.NativeUsage{MaxIssues: 2}).ReadSessions(t.Context(), fw, "rev", in)
	if e != nil || len(r.Issues) != 2 || r.OmittedIssues != 98 || r.Complete {
		t.Fatal(r, e)
	}
}

func TestSessionTuplePairingAndReadFailure(t *testing.T) {
	fw := usageFixture(t, "netscreen")
	at := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	first := "2026-11-01T01:00:00Z fw policy_id=1 session=123 proto=6 src=192.0.2.10 dst=192.0.2.10 src_port=12345 dst_port=443"
	second := strings.ReplaceAll(strings.Replace(first, "12345", "54321", 1), "dst_port=443", "dst_port=80")
	in := analysis.SessionLog{Revision: "rev", GraphDigest: fw.SemanticDigest(), Source: "log", Window: fm.TimeWindow{Start: at, End: at.Add(time.Hour)}, Reader: strings.NewReader(first + "\n" + second)}
	got, err := (analysis.NativeUsage{}).ReadSessions(t.Context(), fw, "rev", in)
	if err != nil || len(got.Tuples) != 2 || got.Tuples[0].Traffic.SourcePort.Low != 12345 || got.Tuples[0].Traffic.DestinationPort.Low != 443 || got.Tuples[1].Traffic.SourcePort.Low != 54321 || got.Tuples[1].Traffic.DestinationPort.Low != 80 {
		t.Fatal(got, err)
	}
	in.Reader = strings.NewReader(strings.Replace(first, " src_port=12345 dst_port=443", "", 1))
	got, err = (analysis.NativeUsage{}).ReadSessions(t.Context(), fw, "rev", in)
	if err != nil || len(got.Tuples) != 0 || len(got.Issues) != 1 {
		t.Fatal("missing ports", got, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	got, err = (analysis.NativeUsage{}).ReadSessions(ctx, fw, "rev", in)
	if !errors.Is(err, context.Canceled) || len(got.Tuples) != 0 {
		t.Fatal(got, err)
	}
	in.Reader = strings.NewReader(first + strings.Repeat("x", 70<<10))
	got, err = (analysis.NativeUsage{}).ReadSessions(t.Context(), fw, "rev", in)
	if err == nil || got.Complete || len(got.Observations) != 0 {
		t.Fatal("truncated line", got, err)
	}
}
func TestASAAmbiguousDeclarationsAndUnusedDoesNotDelete(t *testing.T) {
	fw := usageFixture(t, "asa")
	at := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	sample := func(when time.Time) analysis.CounterSample {
		return analysis.CounterSample{At: when, Source: "counter", Revision: "rev", GraphDigest: fw.SemanticDigest(), Epoch: "generation", Complete: true, Reader: strings.NewReader("access-list inbound line 1 extended permit tcp object-group hosts object-group hosts object-group apps (hitcnt=0)\n")}
	}
	result, err := (analysis.NativeUsage{}).ReadASACounters(t.Context(), fw, "rev", sample(at), sample(at.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := (analysis.Reclaimer{}).Analyze(t.Context(), fw, analysis.ReclamationRequest{At: at.Add(time.Hour), Revision: "rev", Window: fm.TimeWindow{Start: at, End: at.Add(time.Hour)}, Observations: result.Observations})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if !fw.Rule(r.Rule).Builtin() && (r.Unused != analysis.True || r.RemovalCandidate) {
			t.Fatal(r)
		}
	}
	raw := fw.Raw() + "access-list inbound extended permit tcp object-group hosts object-group hosts object-group apps\n"
	duplicated, err := (vendors.Parser{}).Parse(t.Context(), config.Source{Text: raw, Complete: true}, fw.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	fw = duplicated
	result, err = (analysis.NativeUsage{}).ReadASACounters(t.Context(), fw, "rev", sample(at), sample(at.Add(time.Hour)))
	if err != nil || result.Complete {
		t.Fatal(result, err)
	}
	for _, o := range result.Observations {
		if o.Complete || o.Hits > 0 {
			t.Fatal("ambiguous native declaration accepted", o)
		}
	}
}

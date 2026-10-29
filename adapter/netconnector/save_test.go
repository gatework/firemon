package netconnector

import (
	"context"
	"strings"
	"testing"
)

func TestPANJobNativeQueuedTable(t *testing.T) {
	for _, tc := range []struct {
		name, row string
		finished  bool
	}{
		{"queued-position", "2026/01/01 00:00:00          42 1 Commit QUEUED PEND 0%", false},
		{"queued-no-position", "2026/01/01 00:00:00          42   Commit QUEUED PEND 0%", false},
		{"active", "2026/01/01 00:00:00 00:00:01 42   Commit ACT PEND 10%", false},
		{"finished", "2026/01/01 00:00:00 00:00:01 42   Commit FIN OK 00:00:02", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := panJob("Enqueued Dequeued ID PositionInQ Type Status Result Completed\n"+tc.row, "42")
			if err != nil || got != tc.finished {
				t.Fatalf("finished=%v, err=%v", got, err)
			}
		})
	}
}

func TestNativeProfilesCoverApprovedVendors(t *testing.T) {
	for _, vendor := range []string{"srx", "netscreen", "fortinet", "huawei"} {
		t.Run(vendor, func(t *testing.T) {
			if _, err := Profile(vendor); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPANJobRejectsAmbiguousOrUnboundedEvidence(t *testing.T) {
	row := "2026/01/01 00:00:00 00:00:01 42 Commit FIN OK 00:00:02"
	for _, text := range []string{
		strings.Replace(row, "42 Commit", "43 Commit", 1),
		strings.Replace(row, "Commit", "Validate", 1),
		row + "\n" + row,
		"2026/01/01 00:00:00 42 4294967296 Commit QUEUED PEND 0%",
		"2026/01/01 00:00:00 42 Commit QUEUED PEND 101%",
		"2026/01/01 00:00:00 42 Commit FIN OK 00:00:02",
		row + "\nError: commit failed",
	} {
		if done, err := panJob(text, "42"); err == nil || done {
			t.Fatalf("accepted %q: %v %v", text, done, err)
		}
	}
}

func TestPANLocksRequireVendorDocumentedOwnerAttribute(t *testing.T) {
	good := `<response status="success"><result><config-locks><entry name="audit"><name>shared</name><type>config</type><loggedin>yes</loggedin><comment><![CDATA[firemon:token]]></comment></entry></config-locks></result></response>`
	locks, err := parsePANLocks(context.Background(), good, 4096)
	if err != nil || len(locks) != 1 || locks[0].admin != "audit" || locks[0].comment != "firemon:token" {
		t.Fatal(locks, err)
	}
	for _, text := range []string{
		strings.Replace(good, `name="audit"`, ``, 1),
		strings.Replace(good, `<entry name="audit">`, `<entry><admin>audit</admin>`, 1),
		strings.Replace(good, `status="success"`, `status="error"`, 1),
		strings.ReplaceAll(good, "config-locks", "commit-locks"),
		strings.Replace(good, "</comment>", "</comment><comment>other</comment>", 1),
		strings.Replace(good, "<type>config</type>", "<type><entry/></type>", 1),
		good + "<result/>",
	} {
		if _, err := parsePANLocks(context.Background(), text, 4096); err == nil {
			t.Fatalf("accepted ambiguous lock ownership %s", text)
		}
	}
}

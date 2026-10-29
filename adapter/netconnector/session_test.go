package netconnector_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	adapter "github.com/gatework/firemon/adapter/netconnector"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/device"
	"github.com/gatework/go-net-connector/connector"
)

type exchange struct{ command, response string }

const lockToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const emptyPANLocks = `<response status="success"><result><config-locks/></result></response>`
const ownedPANLock = `<response status="success"><result><config-locks><entry name="audit"><name>shared</name><type>config</type><loggedin>yes</loggedin><comment>firemon:` + lockToken + `</comment></entry></config-locks></result></response>`

func panLockDialogue() []exchange {
	return []exchange{
		{"set cli op-command-xml-output on", ""}, {"show config-locks vsys all", emptyPANLocks}, {"set cli op-command-xml-output off", ""},
		{`request config-lock add comment "firemon:` + lockToken + `"`, ""},
		{"set cli op-command-xml-output on", ""}, {"show config-locks vsys all", ownedPANLock}, {"set cli op-command-xml-output off", ""},
		{"show config diff", ""},
	}
}

func panLockCheck() []exchange {
	return []exchange{{"set cli op-command-xml-output on", ""}, {"show config-locks vsys all", ownedPANLock}, {"set cli op-command-xml-output off", ""}}
}

func session(t *testing.T, vendor string, dialogue []exchange) *adapter.Session {
	t.Helper()
	profile := connector.Profile{Name: vendor, LoginPrompt: regexp.MustCompile(`(?m)^fw#\s*$`), CommandPrompt: regexp.MustCompile(`(?m)^fw#\s*$`), CommandTimeout: time.Second}
	return sessionWith(t, vendor, profile, dialogue, adapter.Options{PollInterval: time.Millisecond, MaxPolls: 3})
}

func sessionWith(t *testing.T, vendor string, profile connector.Profile, dialogue []exchange, options adapter.Options) *adapter.Session {
	t.Helper()
	prompt := "fw#"
	beginPAN := vendor == "paloalto" && len(dialogue) > 0 && dialogue[0].command == "configure"
	if vendor == "paloalto" {
		prompt = "audit@fw>"
		profile.LoginPrompt = regexp.MustCompile(`(?m)^audit@fw[>#]\s*$`)
		profile.CommandPrompt = profile.LoginPrompt
		if beginPAN {
			options.ExclusivePANAdmin = true
			dialogue = append(append(panLockDialogue(), panLockCheck()...), dialogue...)
		}
	}
	var peers sync.WaitGroup
	d, err := connector.New(profile, connector.ConnectionConfig{Host: "synthetic", CommandTimeout: time.Second}, connector.WithTransportFactory(func(context.Context, connector.ConnectionConfig) (io.ReadWriteCloser, error) {
		a, b := net.Pipe()
		peers.Add(1)
		go func() {
			defer peers.Done()
			defer b.Close()
			_, _ = io.WriteString(b, prompt)
			scanner := bufio.NewScanner(b)
			for _, event := range dialogue {
				if !scanner.Scan() {
					return
				}
				if scanner.Text() != event.command {
					t.Errorf("command %q, want %q", scanner.Text(), event.command)
					return
				}
				_, _ = io.WriteString(b, event.command+"\r\n"+event.response+"\r\n"+prompt)
			}
			if scanner.Scan() {
				t.Errorf("unexpected command after transcript: %q", scanner.Text())
			}
		}()
		return a, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	metadata := fm.Metadata{Device: "fw", Vendor: vendor}
	if vendor == "fortinet" {
		metadata.Context = "blue"
	}
	s, err := adapter.New(d, metadata, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(); peers.Wait() })
	if beginPAN {
		if err := s.BeginConfiguration(context.Background(), lockToken); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestReadKeepsRunningAndSavedViewsDistinct(t *testing.T) {
	for _, tc := range []struct{ vendor, pager, saved, text string }{
		{"asa", "terminal pager 0", "show startup-config", "hostname saved\ninterface inside0\n nameif inside\n!"},
		{"hillstone", "terminal length 0", "show configuration startup", "hostname saved\nzone inside\nexit"},
		{"paloalto", "set cli pager off", "show config saved running-config.xml", `<config version="11.1"><shared/></config>`},
	} {
		t.Run(tc.vendor, func(t *testing.T) {
			profile := connector.Profile{Name: tc.vendor, LoginPrompt: regexp.MustCompile(`(?m)^fw#\s*$`), CommandPrompt: regexp.MustCompile(`(?m)^fw#\s*$`), ConfigCommands: []string{"show current"}}
			s := sessionWith(t, tc.vendor, profile, []exchange{{"show current", "hostname current"}, {tc.pager, ""}, {tc.saved, tc.text}}, adapter.Options{})
			running, err := s.Read(context.Background(), device.Running)
			if err != nil || !running.Source.Complete || running.Source.Text != "hostname current" || running.Metadata.Device != "fw" || running.Metadata.CapturedAt.IsZero() {
				t.Fatal(running, err)
			}
			saved, err := s.Read(context.Background(), device.Saved)
			if err != nil || !saved.Source.Complete || saved.Source.Text != tc.text || saved.Metadata.Vendor != tc.vendor {
				t.Fatal(saved, err)
			}
		})
	}
}

func TestReadRejectsEmptySavedCaptureAndRetires(t *testing.T) {
	s := session(t, "asa", []exchange{{"terminal pager 0", ""}, {"show startup-config", ""}})
	c, err := s.Read(context.Background(), device.Saved)
	if !errors.Is(err, adapter.ErrCapture) || c.Source.Complete {
		t.Fatal(c, err)
	}
	if _, err := s.Read(context.Background(), device.Running); !errors.Is(err, adapter.ErrRetired) {
		t.Fatal(err)
	}
}

func TestPANSaveWaitsForMatchingCommitJobAndDoesNotReplay(t *testing.T) {
	for _, tc := range []struct {
		name, status string
		success      bool
	}{{"success", "FIN OK", true}, {"failed", "FIN FAIL", false}, {"wrong-type", "FIN OK", false}} {
		t.Run(tc.name, func(t *testing.T) {
			kind := "Commit"
			if tc.name == "wrong-type" {
				kind = "Validate"
			}
			s := session(t, "paloalto", []exchange{{"configure", ""}, {"commit", "Commit job enqueued with jobid 42"}, {"exit", ""}, {"show jobs id 42", "2026/01/01 00:00:00 00:00:00 42 Commit ACT PEND 00:00:01"}, {"show jobs id 42", "2026/01/01 00:00:00 00:00:00 42 " + kind + " " + tc.status + " 00:00:02"}})
			var receipts []deploy.Receipt
			r, err := s.Save(context.Background(), func(_ context.Context, r deploy.Receipt) error { receipts = append(receipts, r); return nil })
			if (err == nil) != tc.success || r.Durable != tc.success || len(receipts) != map[bool]int{true: 1, false: 0}[tc.success] {
				t.Fatal(r, receipts, err)
			}
			if !tc.success {
				if _, err := s.Save(context.Background(), func(context.Context, deploy.Receipt) error { return nil }); !errors.Is(err, adapter.ErrRetired) {
					t.Fatal("failed save reused session", err)
				}
			}
		})
	}
}

func TestPANCommitPollsQueuedMissingDequeueThenActiveThenFinished(t *testing.T) {
	s := session(t, "paloalto", []exchange{
		{"configure", ""}, {"commit", "Commit job enqueued with jobid 42"}, {"exit", ""},
		{"show jobs id 42", "2026/01/01 00:00:00    42 1 Commit QUEUED PEND 0%"},
		{"show jobs id 42", "2026/01/01 00:00:00 00:00:01 42 Commit ACT PEND 50%"},
		{"show jobs id 42", "2026/01/01 00:00:00 00:00:01 42 Commit FIN OK 00:00:02"},
	})
	out, err := s.Save(context.Background(), func(context.Context, deploy.Receipt) error { return nil })
	if err != nil || !out.Durable {
		t.Fatal(out, err)
	}
}

func TestPANConfigLockOwnershipAndCrashCleanup(t *testing.T) {
	for _, tc := range []struct {
		name, locks, diff string
		release, success  bool
	}{
		{"owned-clean", ownedPANLock, "", true, true},
		{"auto-released", emptyPANLocks, "", false, true},
		{"foreign-token", strings.ReplaceAll(ownedPANLock, lockToken, strings.Repeat("b", 48)), "", false, false},
		{"foreign-admin", strings.ReplaceAll(ownedPANLock, `name="audit"`, `name="other"`), "", false, false},
		{"dirty-candidate", ownedPANLock, "+set shared address pending ip-netmask 192.0.2.1", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialogue := []exchange{{"set cli op-command-xml-output on", ""}, {"show config-locks vsys all", tc.locks}, {"set cli op-command-xml-output off", ""}}
			if tc.name != "foreign-token" && tc.name != "foreign-admin" {
				dialogue = append(dialogue, exchange{"show config diff", tc.diff})
			}
			if tc.release {
				dialogue = append(dialogue, exchange{"request config-lock remove", ""}, exchange{"set cli op-command-xml-output on", ""}, exchange{"show config-locks vsys all", emptyPANLocks}, exchange{"set cli op-command-xml-output off", ""})
			}
			p, err := adapter.Profile("paloalto")
			if err != nil {
				t.Fatal(err)
			}
			s := sessionWith(t, "paloalto", p, dialogue, adapter.Options{ExclusivePANAdmin: true})
			if err := s.EndConfiguration(context.Background(), lockToken); (err == nil) != tc.success {
				t.Fatal(err)
			}
		})
	}
}

func TestPANAcquisitionRejectsExistingLockAndRequiresExclusiveAdmin(t *testing.T) {
	for _, exclusive := range []bool{false, true} {
		t.Run(map[bool]string{false: "shared-admin", true: "existing-lock"}[exclusive], func(t *testing.T) {
			var dialogue []exchange
			if exclusive {
				dialogue = []exchange{{"set cli op-command-xml-output on", ""}, {"show config-locks vsys all", ownedPANLock}, {"set cli op-command-xml-output off", ""}}
			}
			p, err := adapter.Profile("paloalto")
			if err != nil {
				t.Fatal(err)
			}
			s := sessionWith(t, "paloalto", p, dialogue, adapter.Options{ExclusivePANAdmin: exclusive})
			if err := s.BeginConfiguration(context.Background(), lockToken); !errors.Is(err, adapter.ErrConfigurationLock) {
				t.Fatal(err)
			}
		})
	}
}

func TestASASaveRequiresPersistenceTextAndReceiptCallbackStopsScript(t *testing.T) {
	t.Run("prompt-only", func(t *testing.T) {
		s := session(t, "asa", []exchange{{"write memory", ""}})
		r, err := s.Save(context.Background(), func(context.Context, deploy.Receipt) error { return nil })
		if err == nil || r.Durable {
			t.Fatal("prompt counted as durable", r, err)
		}
	})
	t.Run("confirmed", func(t *testing.T) {
		s := session(t, "asa", []exchange{{"write memory", "Building configuration...\nCryptochecksum: synthetic\n[OK]"}})
		r, err := s.Save(context.Background(), func(_ context.Context, r deploy.Receipt) error {
			if !r.Durable || r.ResponseDigest == "" {
				t.Fatal(r)
			}
			return nil
		})
		if err != nil || !r.Durable {
			t.Fatal(r, err)
		}
	})
	t.Run("receipt-failed", func(t *testing.T) {
		s := session(t, "asa", []exchange{{"one", "accepted"}})
		failure := errors.New("journal unavailable")
		_, err := s.Execute(context.Background(), []string{"one", "two"}, func(context.Context, deploy.Receipt) error { return failure })
		if !errors.Is(err, failure) {
			t.Fatal(err)
		}
	})
}

func TestSRXRejectsPreexistingCandidateChanges(t *testing.T) {
	s := session(t, "srx", []exchange{
		{"configure exclusive", "Entering configuration mode\n[edit]"},
		{"show | compare | no-more", "[edit security]\n+ policies"},
	})
	if err := s.BeginConfiguration(context.Background(), lockToken); !errors.Is(err, adapter.ErrCandidate) {
		t.Fatal(err)
	}
	if _, err := s.Execute(context.Background(), []string{"configure", "set system host-name unsafe", "exit"}, func(context.Context, deploy.Receipt) error { return nil }); !errors.Is(err, adapter.ErrRetired) {
		t.Fatal(err)
	}
}

func TestFortinetSavedRequiresAutomaticPersistence(t *testing.T) {
	for _, mode := range []string{"manual", "revert", "", "automatic\nset cfg-save manual"} {
		t.Run(mode, func(t *testing.T) {
			s := session(t, "fortinet", []exchange{
				{"get system status", "Current virtual domain: blue\nVirtual domain configuration: disable"},
				{"show full-configuration system global", "config system global\nset cfg-save " + mode + "\nend"},
			})
			capture, err := s.Read(context.Background(), device.Saved)
			if !errors.Is(err, adapter.ErrPersistence) || capture.Source.Complete {
				t.Fatal(capture, err)
			}
		})
	}
}

func TestFortinetMissingVDOMDoesNotIssueEdit(t *testing.T) {
	s := session(t, "fortinet", []exchange{
		{"get system status", "Current virtual domain: root\nVirtual domain configuration: enable"},
		{"config global", ""},
		{"diagnose sys vd list", "name=root index=0 enabled\nname=unrelated index=1 enabled"},
	})
	if capture, err := s.Read(context.Background(), device.Running); !errors.Is(err, adapter.ErrCapture) || capture.Source.Complete {
		t.Fatal(capture, err)
	}
}

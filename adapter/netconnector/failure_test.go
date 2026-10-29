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

func controlled(t *testing.T, vendor string, serve func(net.Conn)) *adapter.Session {
	t.Helper()
	profile := connector.Profile{Name: vendor, LoginPrompt: regexp.MustCompile(`(?m)^fw#\s*$`), CommandPrompt: regexp.MustCompile(`(?m)^fw#\s*$`)}
	prompt := "fw#"
	if vendor == "paloalto" {
		prompt = "audit@fw>"
		profile.LoginPrompt = regexp.MustCompile(`(?m)^(?:audit@fw>|fw#)\s*$`)
		profile.CommandPrompt = profile.LoginPrompt
	}
	var peers sync.WaitGroup
	d, err := connector.New(profile, connector.ConnectionConfig{Host: "synthetic", CommandTimeout: time.Second}, connector.WithTransportFactory(func(context.Context, connector.ConnectionConfig) (io.ReadWriteCloser, error) {
		a, b := net.Pipe()
		peers.Add(1)
		go func() {
			defer peers.Done()
			defer b.Close()
			_, _ = io.WriteString(b, prompt)
			if vendor == "paloalto" {
				r := bufio.NewReader(b)
				for _, event := range append(panLockDialogue(), panLockCheck()...) {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimSpace(line) != event.command {
						t.Errorf("lock command %q, want %q", line, event.command)
						return
					}
					_, _ = io.WriteString(b, event.command+"\r\n"+event.response+"\r\n"+prompt)
				}
			}
			serve(b)
		}()
		return a, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	s, err := adapter.New(d, fm.Metadata{Device: "fw", Vendor: vendor}, adapter.Options{PollInterval: 5 * time.Second, MaxPolls: 3, ExclusivePANAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(); peers.Wait() })
	if vendor == "paloalto" {
		if err := s.BeginConfiguration(context.Background(), lockToken); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestPartialWriteRetainsUncertainReceiptAndCannotReplay(t *testing.T) {
	s := controlled(t, "asa", func(peer net.Conn) { data := make([]byte, 3); _, _ = io.ReadFull(peer, data) })
	var receipts []deploy.Receipt
	out, err := s.Execute(context.Background(), []string{"configure terminal", "end"}, func(_ context.Context, r deploy.Receipt) error { receipts = append(receipts, r); return nil })
	if err == nil || out.Complete || len(receipts) != 1 || !receipts[0].Written || receipts[0].Confirmed || receipts[0].Index != 0 {
		t.Fatal(out, receipts, err)
	}
	if _, err := s.Execute(context.Background(), []string{"configure terminal"}, func(context.Context, deploy.Receipt) error { return nil }); !errors.Is(err, adapter.ErrRetired) {
		t.Fatal(err)
	}
}

func TestDeviceRejectionWithPromptIsNotAConfirmedCommand(t *testing.T) {
	profile := connector.Profile{Name: "asa", LoginPrompt: regexp.MustCompile(`(?m)^fw#\s*$`), CommandPrompt: regexp.MustCompile(`(?m)^fw#\s*$`), CommandErrors: []*regexp.Regexp{regexp.MustCompile(`(?m)^ERROR:`)}}
	s := sessionWith(t, "asa", profile, []exchange{{"bad command", "ERROR: denied"}}, adapter.Options{})
	var receipts []deploy.Receipt
	out, err := s.Execute(context.Background(), []string{"bad command", "next"}, func(_ context.Context, r deploy.Receipt) error { receipts = append(receipts, r); return nil })
	if !errors.Is(err, connector.ErrDevice) || out.Complete || len(receipts) != 1 || !receipts[0].Written || receipts[0].Confirmed {
		t.Fatal(out, receipts, err)
	}
}

func TestCallbackReentryIsBusyAndCloseInterruptsWithoutDeadlock(t *testing.T) {
	s := session(t, "asa", []exchange{{"one", "accepted"}})
	_, err := s.Execute(context.Background(), []string{"one", "two"}, func(ctx context.Context, r deploy.Receipt) error {
		if _, err := s.Save(ctx, func(context.Context, deploy.Receipt) error { return nil }); !errors.Is(err, adapter.ErrBusy) {
			t.Fatal(err)
		}
		return s.Close()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestCommitPollingCancellationOrCloseDoesNotRepeatCommit(t *testing.T) {
	for _, closeSession := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "close"}[closeSession], func(t *testing.T) {
			pending := make(chan struct{})
			s := controlled(t, "paloalto", func(peer net.Conn) {
				scanner := bufio.NewScanner(peer)
				for _, event := range []exchange{{"configure", ""}, {"commit", "Commit job enqueued with jobid 42"}, {"exit", ""}, {"show jobs id 42", "2026/01/01 00:00:00 00:00:00 42 Commit ACT PEND 00:00:01"}} {
					if !scanner.Scan() {
						return
					}
					if scanner.Text() != event.command {
						t.Errorf("unexpected command %q", scanner.Text())
						return
					}
					_, _ = io.WriteString(peer, event.command+"\r\n"+event.response+"\r\nfw#")
				}
				close(pending)
				if scanner.Scan() {
					t.Errorf("command after cancellation: %q", scanner.Text())
				}
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := s.Save(ctx, func(context.Context, deploy.Receipt) error {
					t.Error("pending job produced durable receipt")
					return nil
				})
				done <- err
			}()
			select {
			case <-pending:
			case <-time.After(2 * time.Second):
				t.Fatal("job poll never reached")
			}
			if closeSession {
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not interrupt poll interval")
			}
		})
	}
}

func TestPANPersistenceRejectsWrongOrMalformedJobEvidence(t *testing.T) {
	for _, row := range []string{
		"2026/01/01 00:00:00 00:00:00 41 Commit FIN OK 00:00:01",
		"2026/01/01 00:00:00 invalid 42 Commit FIN OK 00:00:01",
		"2026/01/01 00:00:00 00:00:00 42 Commit FIN OK invalid",
		"2026/01/01 00:00:00 00:00:00 42 Commit FIN OK 00:00:01\n2026/01/01 00:00:00 00:00:00 42 Commit FIN OK 00:00:01",
	} {
		t.Run(row, func(t *testing.T) {
			s := session(t, "paloalto", []exchange{{"configure", ""}, {"commit", "Commit job enqueued with jobid 42"}, {"exit", ""}, {"show jobs id 42", row}})
			out, err := s.Save(context.Background(), func(context.Context, deploy.Receipt) error { t.Error("invalid job produced receipt"); return nil })
			if err == nil || out.Durable {
				t.Fatal(out, err)
			}
		})
	}
}

func TestASAPersistenceRejectsFailureBeforeTerminalRepaint(t *testing.T) {
	s := session(t, "asa", []exchange{{"write memory", "Building configuration...\nError: disk failure\r                    \r[OK]"}})
	out, err := s.Save(context.Background(), func(context.Context, deploy.Receipt) error { t.Error("failed save produced receipt"); return nil })
	if !errors.Is(err, adapter.ErrPersistence) || out.Durable {
		t.Fatal(out, err)
	}
}

func TestInputValidationPrecedesWritesAndReceiptFailureRetires(t *testing.T) {
	s := session(t, "asa", []exchange{{"one", "accepted"}})
	if _, err := s.Execute(context.Background(), []string{"one\ntwo"}, func(context.Context, deploy.Receipt) error { return nil }); !errors.Is(err, adapter.ErrInvalid) {
		t.Fatal(err)
	}
	failure := errors.New("journal unavailable")
	out, err := s.Execute(context.Background(), []string{"one"}, func(context.Context, deploy.Receipt) error { return failure })
	if !out.Complete || !errors.Is(err, failure) {
		t.Fatal(out, err)
	}
	if _, err := s.Execute(context.Background(), []string{"one"}, func(context.Context, deploy.Receipt) error { return nil }); !errors.Is(err, adapter.ErrRetired) {
		t.Fatal(err)
	}
}

func TestSavedXMLRequiresACompleteConfigurationRoot(t *testing.T) {
	for _, text := range []string{`<response status="success"><result/></response>`, `<config><shared/></config><config/>`, `<config>`, strings.Repeat(" ", 3)} {
		t.Run(text, func(t *testing.T) {
			s := session(t, "paloalto", []exchange{{"set cli pager off", ""}, {"show config saved running-config.xml", text}})
			capture, err := s.Read(context.Background(), device.Saved)
			if !errors.Is(err, adapter.ErrCapture) || capture.Source.Complete {
				t.Fatal(capture, err)
			}
		})
	}
}

func TestCommitPollAndOutputBudgetsStopTheConversation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		polls int
		bytes int64
	}{
		{"poll-count", 2, 0}, {"cumulative-output", 3, 2048},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := connector.Profile{Name: "paloalto", LoginPrompt: regexp.MustCompile(`(?m)^fw#\s*$`), CommandPrompt: regexp.MustCompile(`(?m)^fw#\s*$`)}
			pending := "2026/01/01 00:00:00 00:00:00 42 Commit ACT PEND 00:00:01"
			if tc.bytes > 0 {
				pending += "\n" + strings.Repeat("synthetic detail ", 80)
			}
			s := sessionWith(t, "paloalto", profile, []exchange{{"configure", ""}, {"commit", "Commit job enqueued with jobid 42"}, {"exit", ""}, {"show jobs id 42", pending}, {"show jobs id 42", pending}}, adapter.Options{PollInterval: time.Millisecond, MaxPolls: tc.polls, MaxOutputBytes: tc.bytes})
			out, err := s.Save(context.Background(), func(context.Context, deploy.Receipt) error { t.Error("unfinished job produced receipt"); return nil })
			if err == nil || out.Durable {
				t.Fatal(out, err)
			}
			if tc.bytes > 0 && !errors.Is(err, adapter.ErrLimit) && !errors.Is(err, connector.ErrScriptLimit) {
				t.Fatal("output budget was not enforced", err)
			}
			if _, err := s.Save(context.Background(), func(context.Context, deploy.Receipt) error { return nil }); !errors.Is(err, adapter.ErrRetired) {
				t.Fatal(err)
			}
		})
	}
}

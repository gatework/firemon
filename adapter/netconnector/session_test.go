package netconnector_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"regexp"
	"sync"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	adapter "github.com/gatework/firemon/adapter/netconnector"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/go-net-connector/connector"
)

type exchange struct{ command, response string }

func session(t *testing.T, vendor string, dialogue []exchange) *adapter.Session {
	t.Helper()
	profile := connector.Profile{Name: vendor, LoginPrompt: regexp.MustCompile(`(?m)^fw#\s*$`), CommandPrompt: regexp.MustCompile(`(?m)^fw#\s*$`), CommandTimeout: time.Second}
	return sessionWith(t, vendor, profile, dialogue, adapter.Options{PollInterval: time.Millisecond, MaxPolls: 3})
}

func sessionWith(t *testing.T, vendor string, profile connector.Profile, dialogue []exchange, options adapter.Options) *adapter.Session {
	t.Helper()
	prompt := "fw#"
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
	s, err := adapter.New(d, fm.Metadata{Device: "fw", Vendor: vendor}, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(); peers.Wait() })
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
			running, err := s.Read(context.Background(), deploy.Running)
			if err != nil || !running.Source.Complete || running.Source.Text != "hostname current" || running.Metadata.Device != "fw" || running.Metadata.CapturedAt.IsZero() {
				t.Fatal(running, err)
			}
			saved, err := s.Read(context.Background(), deploy.Saved)
			if err != nil || !saved.Source.Complete || saved.Source.Text != tc.text || saved.Metadata.Vendor != tc.vendor {
				t.Fatal(saved, err)
			}
		})
	}
}

func TestReadRejectsEmptySavedCaptureAndRetires(t *testing.T) {
	s := session(t, "asa", []exchange{{"terminal pager 0", ""}, {"show startup-config", ""}})
	c, err := s.Read(context.Background(), deploy.Saved)
	if !errors.Is(err, adapter.ErrCapture) || c.Source.Complete {
		t.Fatal(c, err)
	}
	if _, err := s.Read(context.Background(), deploy.Running); !errors.Is(err, adapter.ErrRetired) {
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

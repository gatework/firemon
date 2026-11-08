package netconnector_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	adapter "github.com/gatework/firemon/adapter/netconnector"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/go-net-connector/connector"
)

// Native profiles determine command acceptance; the peer only supplies wire evidence.
func saveSession(t *testing.T, vendor, prompt string, echoPrompt bool, dialogue []exchange) *adapter.Session {
	t.Helper()
	profile, err := adapter.Profile(vendor)
	if err != nil {
		t.Fatal(err)
	}
	if vendor == "asa" {
		dialogue = append([]exchange{{"enable", ""}}, dialogue...)
	}
	var peers sync.WaitGroup
	d, err := connector.New(profile, connector.ConnectionConfig{Host: "synthetic", CommandTimeout: time.Second}, connector.WithTransportFactory(func(context.Context, connector.ConnectionConfig) (io.ReadWriteCloser, error) {
		a, b := net.Pipe()
		peers.Go(func() {
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
				echo := event.command
				if echoPrompt {
					echo = prompt + event.command
				}
				switch event.command {
				case "configure", "configure exclusive":
					prompt = strings.TrimSuffix(prompt, ">") + "#"
				case "exit":
					prompt = strings.TrimSuffix(prompt, "#") + ">"
				}
				if _, err := io.WriteString(b, echo+"\r\n"+event.response+"\r\n"+prompt); err != nil {
					return
				}
			}
			if scanner.Scan() {
				t.Errorf("unexpected command after transcript: %q", scanner.Text())
			}
		})
		return a, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	metadata := fm.Metadata{Device: "fw", Vendor: vendor}
	if vendor == "fortinet" {
		metadata.Context = "root"
	}
	s, err := adapter.New(d, metadata, adapter.Options{ExclusivePANAdmin: true, PollInterval: time.Millisecond})
	if err != nil {
		_ = d.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(); peers.Wait() })
	return s
}

func TestSaveKeepsPromptNamesOutsidePersistenceEvidence(t *testing.T) {
	for _, tc := range []struct {
		vendor, prompt string
		begin, echo    bool
		dialogue       []exchange
	}{
		{
			vendor: "asa", prompt: "error-fw#", echo: true,
			dialogue: []exchange{{"write memory", "Building configuration...\n\x1b[32m[OK]\x1b[0m"}},
		},
		{
			vendor: "netscreen", prompt: "failed-fw->", echo: true,
			dialogue: []exchange{
				{"save", ""},
				{"get config", "set hostname error-fw"},
				{"get config saved", "set hostname error-fw"},
			},
		},
		{
			vendor: "srx", prompt: "audit@denied-fw>", begin: true,
			dialogue: []exchange{
				{"configure exclusive", "Entering configuration mode\n[edit]"},
				{"show | compare | no-more", "[edit]"},
				{`commit comment "firemon:` + lockToken + `"`, "commit complete\n[edit]"},
			},
		},
		{
			vendor: "paloalto", prompt: "audit@error-fw>", begin: true,
			dialogue: append(append(panLockDialogue(), panLockCheck()...), []exchange{
				{"configure", ""},
				{"commit", "Commit job enqueued with jobid 42"},
				{"exit", ""},
				{"show jobs id 42", "2026/01/01 00:00:00 00:00:01 42 Commit FIN OK 00:00:02"},
			}...),
		},
	} {
		t.Run(tc.vendor, func(t *testing.T) {
			s := saveSession(t, tc.vendor, tc.prompt, tc.echo, tc.dialogue)
			if tc.begin {
				if err := s.BeginConfiguration(t.Context(), lockToken); err != nil {
					t.Fatal(err)
				}
			}
			var receipts []deploy.Receipt
			out, err := s.Save(t.Context(), func(_ context.Context, r deploy.Receipt) error {
				receipts = append(receipts, r)
				return nil
			})
			if err != nil || !out.Complete || !out.Durable || len(receipts) != 1 || !receipts[0].Durable || !receipts[0].Confirmed {
				t.Fatalf("out=%+v receipts=%+v err=%v", out, receipts, err)
			}
		})
	}
}

func TestSaveRetainsRejectionBeforeTerminalEdits(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"prompt-name-in-body", "Building configuration...\nerror-fw#\n[OK]"},
		{"carriage-return", "Building configuration...\nfailed to save\r              \r[OK]"},
		{"cursor-erase", "Building configuration...\nfailed to save\x1b[2K\r[OK]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := saveSession(t, "asa", "error-fw#", true, []exchange{{"write memory", tc.body}})
			out, err := s.Save(t.Context(), func(context.Context, deploy.Receipt) error {
				t.Error("rejected save produced a receipt")
				return nil
			})
			if err == nil || out.Durable || out.Complete {
				t.Fatalf("out=%+v err=%v", out, err)
			}
			if _, err := s.Save(t.Context(), func(context.Context, deploy.Receipt) error { return nil }); !errors.Is(err, adapter.ErrRetired) {
				t.Fatalf("rejected session reused: %v", err)
			}
		})
	}
}

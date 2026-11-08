package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
)

func TestRequestCLITextAndRowErrors(t *testing.T) {
	root := t.TempDir()
	store, err := snapshot.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	const raw = "set zone inside network layer3 ethernet1/1\nset zone outside network layer3 ethernet1/2\nset network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24\nset network interface ethernet ethernet1/2 layer3 ip 198.51.100.1/24\n"
	fw, err := (vendors.Parser{}).Parse(t.Context(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "fw", Vendor: "paloalto"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Publish(t.Context(), fw, snapshot.PublishOptions{PublicationID: "simple"}); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(file, []byte(`{"requests":[{"src":"invalid","dst":"198.51.100.2"},{"src":"192.0.2.2","dst":"198.51.100.2","service":"udp/53"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		rows int
	}{
		{"text", []string{"--src", " １９２.０.２.２ ; 192.0.2.2 ", "--dst", "198.51.100.2", "--service", "４４３", "--at", "2026-11-09T00:00:00Z"}, 1},
		{"window", []string{"--src", "192.0.2.2", "--dst", "198.51.100.2", "--start", "2026-11-09T00:00:00Z", "--end", "2026-11-09T01:00:00Z"}, 1},
		{"file", []string{"--file", file}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			args := append([]string{"request-query", "--store", root}, tc.args...)
			if err := execute(t.Context(), args, &out); err != nil {
				t.Fatal(err)
			}
			var report operations.ReportDocument
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if len(report.Inputs) != tc.rows {
				t.Fatal(out.String())
			}
			row := report.Inputs[tc.rows-1]
			if row.Error != nil || row.Normalized == nil || len(row.Normalized.Sources) != 1 || len(row.Outcomes) == 0 {
				t.Fatal(row)
			}
			if tc.name == "file" && (report.Inputs[0].Error == nil || report.Inputs[0].Error.Field != "src" || len(report.Inputs[0].Outcomes) != 0) {
				t.Fatal("invalid row suppressed sibling", report.Inputs)
			}
			for _, outcome := range row.Outcomes {
				if !outcome.Conditional || outcome.TrafficView == "" {
					t.Fatal("inferred path lost context", outcome)
				}
				if tc.name == "window" && (outcome.Window == nil || outcome.Window.End.Sub(outcome.Window.Start) != time.Hour) {
					t.Fatal(outcome)
				}
			}
			if tc.name == "text" && (row.Normalized.AllServices || row.Normalized.Services[0].Protocol.Low != 6 || row.Normalized.Services[0].DestinationPort.Low != 443) {
				t.Fatal(row.Normalized)
			}
		})
	}
}

func TestRequestCLIRejectsConflictingInputAndTime(t *testing.T) {
	for _, args := range [][]string{
		{"--file", "requests.json", "--src", "192.0.2.1"},
		{"--src", "192.0.2.1"},
		{"--src", "192.0.2.1", "--dst", "198.51.100.1", "--at", "yesterday"},
		{"--src", "192.0.2.1", "--dst", "198.51.100.1", "--start", "2026-11-09T00:00:00Z"},
		{"--src", "192.0.2.1", "--dst", "198.51.100.1", "--at", "2026-11-09T00:00:00Z", "--start", "2026-11-09T00:00:00Z", "--end", "2026-11-09T01:00:00Z"},
		{"--src", "192.0.2.1", "--dst", "198.51.100.1", "--start", "2026-11-09T01:00:00Z", "--end", "2026-11-09T00:00:00Z"},
	} {
		command := append([]string{"request-query", "--store", t.TempDir()}, args...)
		if err := execute(t.Context(), command, &bytes.Buffer{}); err == nil {
			t.Fatal("invalid CLI input accepted", args)
		}
	}
}

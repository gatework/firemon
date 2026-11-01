package main

import (
	"bytes"
	"context"
	"encoding/json"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
	"os"
	"path/filepath"
	"testing"
)

func TestRequestCLIUsesReloadedSnapshotsAndExactEntries(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := snapshot.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	raw := "set zone inside network layer3 ethernet1/1\nset zone outside network layer3 ethernet1/2\nset network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24\nset network interface ethernet ethernet1/2 layer3 ip 198.51.100.1/24\n"
	fw, err := (vendors.Parser{}).Parse(ctx, config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "fw", Vendor: "paloalto"})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := store.Publish(ctx, fw, snapshot.PublishOptions{PublicationID: "seed"})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := requestTraffic("192.0.2.1/32", "198.51.100.1/32", "tcp/443")
	b, _ := requestTraffic("192.0.2.2/32", "198.51.100.2/32", "tcp/443")
	traffic, err := a.Union(b, 64)
	if err != nil {
		t.Fatal(err)
	}
	document := operations.RequestDocument{Version: 1, Requests: []operations.AccessDocument{{ID: "paired", Traffic: traffic.Regions(), Targets: []operations.TargetDocument{{Device: "fw", Policy: operations.PolicyDocument{FromZone: "inside", ToZone: "outside"}}}}}}
	file := filepath.Join(t.TempDir(), "request.json")
	data, _ := json.Marshal(document)
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"request-query", "request-plan"} {
		var output bytes.Buffer
		if err := execute(ctx, []string{command, "--store", root, "--file", file}, &output); err != nil {
			t.Fatal(command, err)
		}
		var result operations.ReportDocument
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Version != 1 || len(result.Inputs) != 1 || len(result.Inputs[0].Request.Traffic) != 2 || len(result.Inputs[0].Outcomes) != 1 || len(result.Inputs[0].Outcomes[0].Wire) != 2 {
			t.Fatal(output.String())
		}
		if command == "request-plan" && (len(result.Devices) != 1 || result.Devices[0].Revision != pub.Revision || result.Devices[0].Plan == nil || result.Devices[0].Plan.Digest == "" || len(result.Devices[0].Plan.Targets) != 1) {
			t.Fatal(output.String())
		}
	}
}
func TestRequestCLIRejectsUnknownVersionFieldsAndTrailingJSON(t *testing.T) {
	for _, data := range []string{`{"version":2,"requests":[]}`, `{"version":1,"requests":[],"surprise":true}`, `{"version":1,"requests":[]} {}`, `{"version":1,"requests":[{"id":"bad","traffic":[{}]}]}`} {
		file := filepath.Join(t.TempDir(), "request.json")
		if err := os.WriteFile(file, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if err := execute(context.Background(), []string{"request-query", "--store", t.TempDir(), "--file", file}, &bytes.Buffer{}); err == nil {
			t.Fatal("accepted", data)
		}
	}
}

func TestRequestDocumentAcceptsExplicitRealWireEvidence(t *testing.T) {
	business, _ := requestTraffic("198.51.100.1/32", "192.0.2.10/32", "tcp/443")
	wire, _ := requestTraffic("198.51.100.1/32", "203.0.113.10/32", "tcp/443")
	document := operations.RequestDocument{Version: 1, Requests: []operations.AccessDocument{{ID: "real", View: inventory.Real, Traffic: business.Regions(), WireCandidates: []operations.WireCandidateDocument{{Traffic: wire.Regions(), Target: operations.TargetDocument{Device: "srx", Policy: operations.PolicyDocument{FromZone: "outside"}}}}}}}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	request, err := operations.DecodeBatchRequest(bytes.NewReader(data))
	if err != nil {
		t.Fatal("real candidates rejected by JSON boundary", err)
	}
	if len(request.Requests) != 1 || request.Requests[0].View != inventory.Real || len(request.Requests[0].WireCandidates) != 1 {
		t.Fatal(request)
	}
	same, err := request.Requests[0].WireCandidates[0].Traffic.Equal(wire, 4096)
	if err != nil || !same {
		t.Fatal("wire coordinates lost", request, err)
	}
}

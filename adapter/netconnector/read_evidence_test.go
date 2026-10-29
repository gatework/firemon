package netconnector_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	fm "github.com/gatework/firemon"
	adapter "github.com/gatework/firemon/adapter/netconnector"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
	"github.com/gatework/go-net-connector/connector"
)

type readFault struct {
	vendor, command, payload, mode string
	occurrence                     int
	limit                          int64
	afterResponse                  func()
}

// Every response comes through the real connector profile. Only the selected
// command is interrupted; preparatory output has a distinct marker.
func interruptedFactory(t *testing.T, fault readFault) (adapter.Factory, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var opens, received atomic.Int32
	var peers sync.WaitGroup
	var connections []net.Conn
	metadata := fm.Metadata{Device: "fw", Vendor: fault.vendor}
	if fault.vendor == "fortinet" {
		metadata.Context = "blue"
	}
	factory := adapter.Factory{Options: adapter.Options{MaxOutputBytes: fault.limit}, Resolve: func(context.Context, string) (adapter.Target, error) {
		return adapter.Target{Metadata: metadata, Connection: connector.ConnectionConfig{Host: "synthetic"}, DeviceOptions: []connector.Option{connector.WithTransportFactory(func(context.Context, connector.ConnectionConfig) (io.ReadWriteCloser, error) {
			a, b := net.Pipe()
			connections = append(connections, a)
			opens.Add(1)
			peers.Add(1)
			go func() {
				defer peers.Done()
				defer b.Close()
				prompt := map[string]string{"asa": "fw#", "hillstone": "fw(M)", "paloalto": "audit@fw>", "srx": "audit@fw>", "huawei": "<fw>", "netscreen": "fw->", "fortinet": "FGT #"}[fault.vendor]
				_, _ = io.WriteString(b, prompt)
				scanner := bufio.NewScanner(b)
				for scanner.Scan() {
					command := scanner.Text()
					if command == fault.command && int(received.Add(1)) == max(1, fault.occurrence) {
						response := command + "\r\n" + fault.payload
						if fault.mode != "eof" && fault.mode != "cancel" {
							response += "\r\n" + prompt
						}
						if fault.mode == "budget" {
							// Retain an observed prefix before the next transport chunk
							// reaches the connector's per-response buffer bound.
							for len(response) > 0 {
								n := min(128, len(response))
								if _, err := io.WriteString(b, response[:n]); err != nil {
									break
								}
								response = response[n:]
							}
						} else {
							_, _ = io.WriteString(b, response)
						}
						if fault.mode == "cancel" {
							// A pager reply proves the connector already consumed and
							// retained the configuration prefix before cancellation.
							var reply [1]byte
							if _, err := io.ReadFull(b, reply[:]); err != nil || reply[0] != ' ' {
								t.Errorf("missing pager acknowledgement: %q %v", reply, err)
								return
							}
						}
						if fault.afterResponse != nil {
							fault.afterResponse()
						}
						if fault.mode != "eof" && scanner.Scan() {
							t.Errorf("command after failed capture: %q", scanner.Text())
						}
						return
					}
					body := ""
					switch command {
					case "enable", "terminal pager 0", "terminal length 0", "screen-length 0 temporary", "set cli pager off", "set cli config-output-format set":
						body = "preparation-marker"
					case "su":
						body = "privilege level is 3"
					case "configure":
						prompt = "audit@fw#"
					case "exit":
						prompt = "audit@fw>"
					case "show config diff":
					case "show":
						body = "set address captured ip-netmask 192.0.2.1/32\n[edit]"
					case "get system status":
						body = "Current virtual domain: blue\nVirtual domain configuration: disable"
					case "show full-configuration system global":
						body = "config system global\nset cfg-save automatic\nend"
					default:
						t.Errorf("unexpected command %q", command)
						return
					}
					if _, err := io.WriteString(b, command+"\r\n"+body+"\r\n"+prompt); err != nil {
						return
					}
				}
			}()
			return a, nil
		})}}, nil
	}}
	t.Cleanup(func() {
		for _, c := range connections {
			_ = c.Close()
		}
		peers.Wait()
	})
	return factory, &opens, &received
}

func TestCollectorRetainsInterruptedNativeCaptureWithoutReconnect(t *testing.T) {
	for _, vendor := range []string{"srx", "fortinet"} {
		for _, mode := range []string{"eof", "cancel", "rejected", "budget"} {
			t.Run(vendor+"/"+mode, func(t *testing.T) {
				command := "show configuration | display set | no-more"
				payload := "set interfaces ge-0/0/0 description partial-evidence"
				if vendor == "fortinet" {
					command = "show full-configuration"
					payload = "config firewall address\nedit partial-evidence"
				}
				if mode == "rejected" {
					if vendor == "srx" {
						payload += "\nerror: interrupted capture"
					} else {
						payload += "\nCommand fail. Return code -3"
					}
				}
				if mode == "cancel" {
					if vendor == "srx" {
						payload += "\n---(more)---"
					} else {
						payload += "\n--More--"
					}
				}
				if mode == "budget" {
					payload += strings.Repeat("\n# received-evidence", 100)
				}
				collectCtx, cancel := context.WithCancel(context.Background())
				defer cancel()
				fault := readFault{vendor: vendor, command: command, payload: payload, mode: mode, limit: 512}
				if mode == "cancel" {
					fault.afterResponse = cancel
				}
				factory, opens, reads := interruptedFactory(t, fault)
				store, err := snapshot.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				metadata := fm.Metadata{Device: "fw", Vendor: vendor}
				if vendor == "fortinet" {
					metadata.Context = "blue"
				}
				baseline, err := fm.Seal(fm.Data{Metadata: metadata})
				if err != nil {
					t.Fatal(err)
				}
				base, err := store.Publish(context.Background(), baseline, snapshot.PublishOptions{PublicationID: "base"})
				if err != nil {
					t.Fatal(err)
				}
				collector := operations.Collector{Store: store, Sessions: factory, Parser: vendors.Parser{}}
				request := operations.CollectRequest{Device: "fw", Expected: base.Revision, PublicationID: "interrupted"}
				result, err := collector.Collect(collectCtx, request)
				if !errors.Is(err, operations.ErrIncomplete) || result.Complete || result.Revision == "" {
					t.Fatal(result, err)
				}
				if mode == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation was lost", err)
				}
				if mode == "rejected" && !errors.Is(err, connector.ErrDevice) {
					t.Fatal("native rejection was lost", err)
				}
				stored, loadErr := store.Load(context.Background(), result.Revision)
				if loadErr != nil {
					t.Fatal(loadErr)
				}
				raw := stored.Export().Raw
				if stored.Complete() || raw == "" || len(raw) > 512 || strings.Contains(raw, "preparation-marker") || strings.Contains(raw, "Current virtual domain") || !strings.HasPrefix(payload, raw) {
					t.Fatalf("received configuration evidence lost or misbound: raw=%q complete=%v err=%v", raw, stored.Complete(), err)
				}
				if mode != "budget" && raw != payload {
					t.Fatalf("partial payload changed: got %q want %q", raw, payload)
				}
				if _, _, err := store.Current(context.Background(), "fw"); !errors.Is(err, snapshot.ErrUnavailable) {
					t.Fatal("stale current remained usable", err)
				}
				retry, err := collector.Collect(context.Background(), request)
				if !errors.Is(err, operations.ErrIncomplete) || retry != result || opens.Load() != 1 || reads.Load() != 1 {
					t.Fatal("capture was retried", retry, err, opens.Load(), reads.Load())
				}
			})
		}
	}
}

func TestReadRetainsOnlyMatchingConfigurationCommandEvidence(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fault readFault
		view  deploy.View
		want  string
	}{
		{"srx-saved", readFault{vendor: "srx", command: "show configuration | display set | no-more", payload: "set interfaces ge-0/0/0 description partial", mode: "eof"}, deploy.Saved, "set interfaces ge-0/0/0 description partial"},
		{"fortinet-saved", readFault{vendor: "fortinet", command: "show full-configuration", payload: "config firewall address\nedit partial", mode: "eof"}, deploy.Saved, "config firewall address\nedit partial"},
		{"asa-running", readFault{vendor: "asa", command: "show running-config", payload: "interface inside0\n nameif inside", mode: "eof"}, deploy.Running, "interface inside0\n nameif inside"},
		{"asa-saved", readFault{vendor: "asa", command: "show startup-config", payload: "interface inside0\n nameif inside", mode: "eof"}, deploy.Saved, "interface inside0\n nameif inside"},
		{"hillstone-running", readFault{vendor: "hillstone", command: "show configuration running", payload: "zone inside\nexit", mode: "eof"}, deploy.Running, "zone inside\nexit"},
		{"netscreen-running", readFault{vendor: "netscreen", command: "get config", payload: "set interface ethernet0/1 zone Trust", mode: "eof"}, deploy.Running, "set interface ethernet0/1 zone Trust"},
		{"huawei-running", readFault{vendor: "huawei", command: "dis cur", payload: "firewall zone trust\n add interface GigabitEthernet1/0/1", mode: "eof"}, deploy.Running, "firewall zone trust\n add interface GigabitEthernet1/0/1"},
		{"pan-running", readFault{vendor: "paloalto", command: "show", payload: "set address partial ip-netmask 192.0.2.1/32", mode: "eof"}, deploy.Running, "set address partial ip-netmask 192.0.2.1/32"},
		{"pan-saved", readFault{vendor: "paloalto", command: "show config saved running-config.xml", payload: "<config><shared>", mode: "eof"}, deploy.Saved, "<config><shared>"},
		{"pager-failure", readFault{vendor: "asa", command: "terminal pager 0", payload: "preparation-marker", mode: "eof"}, deploy.Running, ""},
		{"context-failure", readFault{vendor: "fortinet", command: "get system status", payload: "Current virtual domain: blue", mode: "eof"}, deploy.Running, ""},
		{"save-mode-failure", readFault{vendor: "fortinet", command: "show full-configuration system global", payload: "config system global\nset cfg-save", mode: "eof"}, deploy.Saved, ""},
		{"pan-prediff", readFault{vendor: "paloalto", command: "show config diff", payload: "uncommitted-preflight", mode: "rejected"}, deploy.Running, ""},
		{"pan-postdiff", readFault{vendor: "paloalto", command: "show config diff", occurrence: 2, payload: "uncommitted-postflight", mode: "rejected"}, deploy.Running, "set address captured ip-netmask 192.0.2.1/32\n[edit]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			factory, opens, _ := interruptedFactory(t, tc.fault)
			session, err := factory.Open(context.Background(), "fw")
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			capture, err := session.Read(context.Background(), tc.view)
			if err == nil || capture.Source.Complete || capture.Source.Text != tc.want {
				t.Fatalf("capture=%+v err=%v want=%q", capture, err, tc.want)
			}
			if _, err := session.Read(context.Background(), tc.view); !errors.Is(err, adapter.ErrRetired) || opens.Load() != 1 {
				t.Fatal("failed capture did not retire", err, opens.Load())
			}
		})
	}
}

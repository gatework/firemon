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
	"github.com/gatework/firemon/device"
	"github.com/gatework/go-net-connector/connector"
)

func TestFactoryCreatesIndependentDevicesAndASANativeProfile(t *testing.T) {
	var opened atomic.Int32
	var peers sync.WaitGroup
	f := adapter.Factory{Resolve: func(_ context.Context, id string) (adapter.Target, error) {
		return adapter.Target{Metadata: fm.Metadata{Device: id, Vendor: "asa"}, Connection: connector.ConnectionConfig{Host: "synthetic"}, DeviceOptions: []connector.Option{
			connector.WithTransportFactory(func(_ context.Context, cfg connector.ConnectionConfig) (io.ReadWriteCloser, error) {
				if cfg.MaxOutputBytes != 16<<20 || cfg.MaxScriptOutputBytes != 16<<20 {
					t.Errorf("factory did not bound device capture: %d/%d", cfg.MaxOutputBytes, cfg.MaxScriptOutputBytes)
				}
				a, b := net.Pipe()
				opened.Add(1)
				peers.Add(1)
				go func() {
					defer peers.Done()
					defer b.Close()
					_, _ = io.WriteString(b, "fw#")
					scanner := bufio.NewScanner(b)
					for scanner.Scan() {
						cmd := scanner.Text()
						body := ""
						switch cmd {
						case "enable", "terminal pager 0":
						case "show running-config":
							body = "hostname fw\ninterface inside0\n nameif inside\n!"
						default:
							t.Errorf("unexpected command: %q", cmd)
							return
						}
						_, _ = io.WriteString(b, cmd+"\r\n"+body+"\r\nfw#")
					}
				}()
				return a, nil
			}),
		}}, nil
	}}
	a, err := f.Open(context.Background(), "fw")
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.OpenReadOnly(context.Background(), "fw")
	if err != nil {
		_ = a.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close(); peers.Wait() })
	if _, ok := b.(deploy.Session); ok {
		t.Fatal("read-only factory exposed deployment methods")
	}
	if opened.Load() != 2 {
		t.Fatal("factory reused a connection", opened.Load())
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	capture, err := b.Read(context.Background(), device.Running)
	if err != nil || !capture.Source.Complete || !strings.Contains(capture.Source.Text, "interface inside0") || strings.Contains(capture.Source.Text, "fw#") {
		t.Fatal(capture, err)
	}
}

func TestFactoryRejectsWrongIdentityBeforeConnecting(t *testing.T) {
	f := adapter.Factory{Resolve: func(context.Context, string) (adapter.Target, error) {
		return adapter.Target{Metadata: fm.Metadata{Device: "other", Vendor: "asa"}}, nil
	}}
	if _, err := f.Open(context.Background(), "fw"); !errors.Is(err, adapter.ErrInvalid) {
		t.Fatal(err)
	}
}

func TestHillstoneUsesConnectorPersistenceValidation(t *testing.T) {
	profile, err := adapter.Profile("hillstone")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		text string
		ok   bool
	}{{"Saving configuration is finished.", true}, {"", false}, {"Error: flash full\nSaving configuration is finished.", false}} {
		t.Run(tc.text, func(t *testing.T) {
			s := sessionWith(t, "hillstone", profile, []exchange{{"save all", tc.text}}, adapter.Options{})
			out, err := s.Save(context.Background(), func(context.Context, deploy.Receipt) error { return nil })
			if (err == nil) != tc.ok || out.Durable != tc.ok {
				t.Fatal(out, err)
			}
		})
	}
}

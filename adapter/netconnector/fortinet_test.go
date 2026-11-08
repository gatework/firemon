package netconnector_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	adapter "github.com/gatework/firemon/adapter/netconnector"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/device"
)

const fortinetRoot = "Current virtual domain: root\nVirtual domain configuration: disable"

func fortinetMode(text string) []exchange {
	return []exchange{{"get system status", fortinetRoot}, {"show full-configuration system global", text}}
}

func TestFortinetAutomaticModeTreatsSettingValuesAsData(t *testing.T) {
	const global = `config system global
set hostname "error-fw"
set admintitle "failed\" and denied
Error: this is a title"
set cfg-save automatic
end`
	for _, action := range []string{"begin", "read", "save"} {
		t.Run(action, func(t *testing.T) {
			dialogue := fortinetMode(global)
			switch action {
			case "begin":
				dialogue = append(dialogue, exchange{"get system status", fortinetRoot})
			case "read":
				dialogue = append(dialogue, exchange{"get system status", fortinetRoot}, exchange{"show full-configuration", "config system global\nset hostname error-fw\nend"})
				dialogue = append(dialogue, fortinetMode(global)...)
			case "save":
				dialogue = append(dialogue, exchange{"execute cfg save", ""})
				dialogue = append(dialogue, fortinetMode(global)...)
			}
			s := saveSession(t, "fortinet", "error-fw #", true, dialogue)
			switch action {
			case "begin":
				if err := s.BeginConfiguration(t.Context(), lockToken); err != nil {
					t.Fatal(err)
				}
			case "read":
				capture, err := s.Read(t.Context(), device.Saved)
				if err != nil || !capture.Source.Complete {
					t.Fatalf("capture=%+v err=%v", capture, err)
				}
			case "save":
				receipts := 0
				out, err := s.Save(t.Context(), func(_ context.Context, r deploy.Receipt) error {
					receipts++
					if !r.Durable || !r.Confirmed {
						t.Errorf("unconfirmed receipt: %+v", r)
					}
					return nil
				})
				if err != nil || !out.Complete || !out.Durable || receipts != 1 {
					t.Fatalf("out=%+v receipts=%d err=%v", out, receipts, err)
				}
			}
		})
	}
}

func TestFortinetAutomaticModeKeepsEncodedHistory(t *testing.T) {
	// GBK bytes for 中文; connector validates and identifies the wire encoding.
	const global = "config system global\n" +
		"set admintitle \"\xd6\xd0\xce\xc4 failed and denied\"\n" +
		"set cfg-save automatic\nend"
	for _, tc := range []struct {
		name, prefix string
		valid        bool
	}{
		{"gbk-setting", "", true},
		{"gbk-repainted-rejection", "Error: \xd6\xd0\xce\xc4 failed\r" + strings.Repeat(" ", 32) + "\r", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialogue := fortinetMode(tc.prefix + global)
			if tc.valid {
				dialogue = append(dialogue, exchange{"execute cfg save", ""})
				dialogue = append(dialogue, fortinetMode(global)...)
			}
			s := saveSession(t, "fortinet", "error-fw #", true, dialogue)
			receipts := 0
			out, err := s.Save(t.Context(), func(context.Context, deploy.Receipt) error {
				receipts++
				return nil
			})
			if tc.valid {
				if err != nil || !out.Complete || !out.Durable || receipts != 1 {
					t.Fatalf("out=%+v receipts=%d err=%v", out, receipts, err)
				}
			} else {
				if err == nil || out.Complete || out.Durable || receipts != 0 {
					t.Fatalf("out=%+v receipts=%d err=%v", out, receipts, err)
				}
				if _, err := s.Read(t.Context(), device.Saved); !errors.Is(err, adapter.ErrRetired) {
					t.Fatalf("unproved session reused: %v", err)
				}
			}
		})
	}
}

func TestFortinetAutomaticModeRequiresOneGlobalSetting(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"manual", "config system global\nset cfg-save manual\nend"},
		{"revert", "config system global\nset cfg-save revert\nend"},
		{"missing", "config system global\nset hostname fw\nend"},
		{"duplicate", "config system global\nset cfg-save automatic\nset cfg-save automatic\nend"},
		{"conflict", "config system global\nset cfg-save manual\nset cfg-save automatic\nend"},
		{"outside-global", "set cfg-save automatic"},
		{"wrong-section", "config system settings\nset cfg-save automatic\nend"},
		{"nested-section", "config system global\nconfig system settings\nset cfg-save automatic\nend\nend"},
		{"missing-end", "config system global\nset cfg-save automatic"},
		{"trailing-statement", "config system global\nset cfg-save automatic\nend\nset hostname fw"},
		{"rejection", "config system global\nset cfg-save automatic\nend\nError: operation failed"},
		{"repainted-rejection", "Error: operation failed\r                        \rconfig system global\nset cfg-save automatic\nend"},
		{"repainted-mode", "config system global\nset cfg-save manual\r                 \rset cfg-save automatic\nend"},
		{"unclosed-value", "config system global\nset cfg-save automatic\nset admintitle \"unfinished\nend"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := saveSession(t, "fortinet", "FGT #", false, fortinetMode(tc.text))
			out, err := s.Save(t.Context(), func(context.Context, deploy.Receipt) error {
				t.Error("unproved mode produced a receipt")
				return nil
			})
			if err == nil || out.Complete || out.Durable {
				t.Fatalf("out=%+v err=%v", out, err)
			}
			if _, err := s.Read(t.Context(), device.Saved); !errors.Is(err, adapter.ErrRetired) {
				t.Fatalf("unproved session reused: %v", err)
			}
		})
	}
}

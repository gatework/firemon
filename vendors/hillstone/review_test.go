package hillstone_test

import (
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/vendors/hillstone"
)

func compileText(t *testing.T, text string) *firemon.Firewall {
	t.Helper()
	fw, err := firemon.Compile(mustParse(t, hillstone.Options{}, text))
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func TestHa_UnreadableOperandMakesRuleUndecidable(t *testing.T) {
	t.Parallel()
	fw := compileText(t, "rule id 1\n  action deny\n  src-country CN\n  dst-addr \"Any\"\n  service \"Any\"\nexit\nrule id 2\n  action permit\n  src-addr \"Any\"\n  dst-addr \"Any\"\n  service \"Any\"\n  some-new-keyword x\nexit\n")
	for _, id := range []string{"1", "2"} {
		if r, _ := fw.Rule(id); r.Decidable() {
			t.Errorf("rule %s with an unreadable line must not be decidable", id)
		}
	}
}

func TestHc_InvalidObjectLinesAreNotEmptySets(t *testing.T) {
	t.Parallel()
	fw := compileText(t, `address "bad-mask"
  ip 10.150.0.0 10.159.255.255
exit
service "bad-svc"
  tcp dst-port abc
exit
service "with-timeout"
  tcp dst-port 8080 timeout 3600
exit
rule id 1
  action permit
  src-addr "bad-mask"
  dst-addr "Any"
  service "with-timeout"
exit
rule id 2
  action permit
  src-addr "Any"
  dst-addr "Any"
  service "bad-svc"
exit
`)
	for _, id := range []string{"1", "2"} {
		if r, _ := fw.Rule(id); r.Decidable() {
			t.Errorf("rule %s references an object with an invalid line", id)
		}
	}
	if got, ok := fw.Service("with-timeout"); !ok || got.String() != "tcp/8080" {
		t.Errorf("session timeout must not invalidate the service: %s", got)
	}
}

func TestPolicyGlobalNestedRules(t *testing.T) {
	t.Parallel()
	fw := compileText(t, "policy-global\n  rule id 7\n    action permit\n    service \"HTTPS\"\n  exit\nexit\n")
	if _, ok := fw.Rule("7"); !ok {
		t.Fatal("rules nested in policy-global are parsed")
	}
}

func compileConfig(t *testing.T, cfg *firemon.Config) *firemon.Firewall {
	t.Helper()
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

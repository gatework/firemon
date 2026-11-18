package firemon_test

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/gatework/firemon"
)

func TestConfig_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	cfg := sampleConfig()
	cfg.DynamicNATs = []firemon.DynamicNAT{{ID: "1", TranslatedSource: firemon.Translation{Mode: firemon.TranslationModeInterface, Interface: "eth0/0"}}}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var back firemon.Config
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(cfg, &back, cmpopts.IgnoreFields(firemon.Config{}, "Location"), cmpopts.EquateEmpty(), cmp.Comparer(func(a, b interface{ String() string }) bool { return a.String() == b.String() })); diff != "" {
		t.Fatalf("round trip (-want +got):\n%s", diff)
	}
	a, _ := firemon.Compile(cfg)
	b, _ := firemon.Compile(&back)
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("fingerprint changed by a JSON round trip")
	}
}

func TestConfig_RejectsUnknownEnum(t *testing.T) {
	t.Parallel()
	var r firemon.SecurityRule
	if err := json.Unmarshal([]byte(`{"id":"1","action":"allow-ish"}`), &r); err == nil {
		t.Fatal("want error for unknown action")
	}
}

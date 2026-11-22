package traffic_test

import (
	"testing"

	"github.com/gatework/firemon/traffic"
)

func TestDomainSet_Match(t *testing.T) {
	t.Parallel()
	d := traffic.NewDomainSet("Account.Example.org.", "*.example.com", "*mirror.example.net")
	tests := []struct {
		name string
		want bool
	}{
		{"account.example.org", true},
		{"ACCOUNT.EXAMPLE.ORG.", true},
		{"login.account.example.org", false},
		{"a.example.com", true},
		{"a.b.example.com", true},
		{"example.com", false},
		{"*.sub.example.com", true},
		{"*.com", false},
		{"registry.mirror.example.net", true},
		{"mirror.example.net", true},
		{"", false},
	}
	for _, tt := range tests {
		if got := d.Match(tt.name); got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
	if got := d.String(); got != "*.example.com,*mirror.example.net,account.example.org" {
		t.Errorf("String() = %q", got)
	}
}

func FuzzDomainSet(f *testing.F) {
	f.Add("*.example.com", "a.example.com")
	f.Fuzz(func(t *testing.T, pattern, name string) {
		d := traffic.NewDomainSet(pattern)
		if d.Match(name) && !traffic.NewDomainSet(pattern, "other.test").Match(name) {
			t.Fatal("a union must match whatever a member matches")
		}
		if p := traffic.NormalizeDomain(pattern); p != "" && p[0] != '*' && !d.Match(p) {
			t.Fatalf("exact pattern %q must match itself", p)
		}
	})
}

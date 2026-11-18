package traffic_test

import (
	"testing"

	"github.com/gatework/firemon/traffic"
)

func TestDomainSet_Match(t *testing.T) {
	t.Parallel()
	d := traffic.NewDomainSet("Account.Live.com.", "*.example.com", "*npmmirror.com")
	tests := []struct {
		name string
		want bool
	}{
		{"account.live.com", true},
		{"ACCOUNT.LIVE.COM.", true},
		{"login.account.live.com", false},
		{"a.example.com", true},
		{"a.b.example.com", true},
		{"example.com", false},
		{"*.sub.example.com", true},
		{"*.com", false},
		{"registry.npmmirror.com", true},
		{"npmmirror.com", true},
		{"", false},
	}
	for _, tt := range tests {
		if got := d.Match(tt.name); got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
	if got := d.String(); got != "*.example.com,*npmmirror.com,account.live.com" {
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

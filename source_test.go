package firemon_test

import (
	"slices"
	"testing"

	"github.com/gatework/firemon"
)

// A rule's text comes after the objects it names, a group's members before
// the group, each once; predefined objects without text are left out.
func TestConfig_RuleSource(t *testing.T) {
	t.Parallel()
	cfg := &firemon.Config{
		Addresses:     []firemon.Address{{Name: "Any", Predefined: true}},
		AddressGroups: []firemon.AddressGroup{{Name: "web", Members: []string{"w1", "w2"}}},
		ServiceGroups: []firemon.ServiceGroup{{Name: "svc", Members: []string{"https", "tcp-8080"}}},
		Rules: []firemon.SecurityRule{{ID: "7", Source: []firemon.AddressRef{firemon.NamedAddress("w1"), firemon.NamedAddress("Any")},
			Destination: []firemon.AddressRef{firemon.NamedAddress("web")}, Services: []string{"svc"}, Schedule: "work"}},
	}
	cfg.AddSource(firemon.SourceAddress, "Any", "address Any predefined", "exit")
	cfg.AddSource(firemon.SourceAddress, "w1", "address w1", "exit")
	cfg.AddSource(firemon.SourceAddress, "w2", "address w2", "exit")
	cfg.AddSource(firemon.SourceAddressGroup, "web", "group web")
	cfg.AddSource(firemon.SourceService, "tcp-8080", "service tcp-8080")
	cfg.AddSource(firemon.SourceServiceGroup, "svc", "servgroup svc")
	cfg.AddSource(firemon.SourceSchedule, "work", "schedule work")
	cfg.AddSource(firemon.SourceRule, "7", "rule id 7", "exit")
	got, ok := cfg.RuleSource("7")
	want := []string{"address w1", "exit", "address w2", "exit", "group web", "service tcp-8080", "servgroup svc", "schedule work", "rule id 7", "exit"}
	if !ok || !slices.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
	if _, ok := cfg.RuleSource("8"); ok {
		t.Fatal("unknown rule has no source")
	}
}

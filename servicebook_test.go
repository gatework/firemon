package firemon_test

import (
	"encoding/json"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

func TestParseServiceBook(t *testing.T) {
	t.Parallel()
	book, err := firemon.ParseServiceBook([]byte(`{"DNS":["udp/53","tcp/53"],"PING":["icmp/8"],"Any":["any"],"WEB":["tcp/80","tcp/81-90"]}`))
	if err != nil {
		t.Fatal(err)
	}
	set := func(name string) string {
		var s traffic.ServiceSet
		for _, e := range book[name] {
			s = s.Union(e.Set())
		}
		return s.String()
	}
	for name, want := range map[string]string{"DNS": "tcp/53,udp/53", "PING": "icmp/8", "Any": "any", "WEB": "tcp/80-90"} {
		if got := set(name); got != want {
			t.Errorf("%s: got %s, want %s", name, got, want)
		}
	}
	raw, err := json.Marshal(book)
	if err != nil {
		t.Fatal(err)
	}
	again, err := firemon.ParseServiceBook(raw)
	if err != nil || len(again) != len(book) {
		t.Fatalf("round trip: %v %s", err, raw)
	}
}

func TestParseServiceBook_Rejects(t *testing.T) {
	t.Parallel()
	for _, in := range []string{`[]`, `{"X":[]}`, `{"":["tcp/1"]}`, `{"X":["tcp/99999"]}`} {
		if _, err := firemon.ParseServiceBook([]byte(in)); err == nil {
			t.Errorf("%s: want error", in)
		}
	}
}

func TestServiceBook_With(t *testing.T) {
	t.Parallel()
	base := firemon.ServiceBook{"HTTP": {firemon.PortEntry(traffic.ProtocolTCP, traffic.Port(80))}}
	over := firemon.ServiceBook{"HTTP": {firemon.PortEntry(traffic.ProtocolTCP, traffic.Port(8080))}, "X": nil}
	got := base.With(over)
	if got["HTTP"][0].Dst.Low != 8080 || len(got) != 2 || base["HTTP"][0].Dst.Low != 80 {
		t.Fatalf("got %v, base %v", got, base)
	}
	svcs := got.Services(func(name string) bool { return name == "X" })
	if len(svcs) != 1 || svcs[0].Name != "HTTP" || !svcs[0].Predefined {
		t.Fatalf("services %v", svcs)
	}
}

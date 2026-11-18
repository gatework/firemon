package firemon

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/gatework/firemon/traffic"
)

// ServiceBook maps the names of predefined (built-in) services to their
// entries. Built-in services differ by vendor, operating-system version and
// device model, so vendors ship a default book and operators can supply the
// book observed on their devices.
//
// The JSON form maps each name to a list of service expressions in the
// traffic.ParseServiceSet syntax:
//
//	{"HTTP": ["tcp/80"], "DNS": ["tcp/53", "udp/53"], "PING": ["icmp/8"]}
type ServiceBook map[string][]ServiceEntry

// ParseServiceBook decodes the JSON form of a service book.
func ParseServiceBook(data []byte) (ServiceBook, error) {
	var raw map[string][]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("firemon: service book: %w", err)
	}
	book := make(ServiceBook, len(raw))
	for name, exprs := range raw {
		if strings.TrimSpace(name) == "" || len(exprs) == 0 {
			return nil, fmt.Errorf("firemon: service book: service %q needs a name and entries", name)
		}
		var set traffic.ServiceSet
		for _, e := range exprs {
			s, err := traffic.ParseServiceSet(e)
			if err != nil {
				return nil, fmt.Errorf("firemon: service book: %s: %w", name, err)
			}
			set = set.Union(s)
		}
		book[name] = ServiceEntries(set)
	}
	return book, nil
}

// MarshalJSON writes the JSON form with canonical expressions.
func (b ServiceBook) MarshalJSON() ([]byte, error) {
	raw := make(map[string][]string, len(b))
	for name, entries := range b {
		var set traffic.ServiceSet
		for _, e := range entries {
			set = set.Union(e.Set())
		}
		raw[name] = strings.Split(set.String(), ",")
	}
	return json.Marshal(raw)
}

// UnmarshalJSON reads the JSON form written by MarshalJSON.
func (b *ServiceBook) UnmarshalJSON(data []byte) error {
	book, err := ParseServiceBook(data)
	if err != nil {
		return err
	}
	*b = book
	return nil
}

// With returns a copy of b in which the services of over replace those of
// the same name. A nil b and empty over give nil.
func (b ServiceBook) With(over ServiceBook) ServiceBook {
	if b == nil && len(over) == 0 {
		return nil
	}
	out := make(ServiceBook, len(b)+len(over))
	for name, entries := range b {
		out[name] = slices.Clone(entries)
	}
	for name, entries := range over {
		out[name] = slices.Clone(entries)
	}
	return out
}

// Lookup returns the set of name, ignoring case.
func (b ServiceBook) Lookup(name string) (traffic.ServiceSet, bool) {
	entries, ok := b[name]
	if !ok {
		for n, e := range b {
			if strings.EqualFold(n, name) {
				entries, ok = e, true
				break
			}
		}
	}
	var set traffic.ServiceSet
	for _, e := range entries {
		set = set.Union(e.Set())
	}
	return set, ok
}

// Names returns the service names in sorted order.
func (b ServiceBook) Names() []string { return slices.Sorted(maps.Keys(b)) }

// Services returns the book as predefined services, sorted by name,
// leaving out the names for which skip reports true (names the
// configuration declares itself).
func (b ServiceBook) Services(skip func(name string) bool) []Service {
	var out []Service
	for _, name := range b.Names() {
		if skip == nil || !skip(name) {
			out = append(out, Service{Name: name, Entries: slices.Clone(b[name]), Predefined: true})
		}
	}
	return out
}

// ServiceEntries converts a service set into entries, one per protocol and
// port rectangle.
func ServiceEntries(s traffic.ServiceSet) []ServiceEntry {
	var out []ServiceEntry
	for r := range s.All() {
		if r.IsAnyProtocol() && r.Src.IsAny() && r.Dst.IsAny() {
			return []ServiceEntry{{AnyProtocol: true}}
		}
		for p := int(r.ProtocolLow); p <= int(r.ProtocolHigh); p++ {
			out = append(out, ServiceEntry{Protocol: traffic.Protocol(p), Src: r.Src, Dst: r.Dst})
		}
	}
	return out
}

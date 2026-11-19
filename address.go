package firemon

import (
	"net/netip"

	"github.com/gatework/firemon/traffic"
)

// AddressKind distinguishes the forms an address entry takes.
type AddressKind uint8

// Address entry kinds.
const (
	AddressKindUnset AddressKind = iota
	// AddressKindPrefix is a host or subnet, for example 10.0.0.0/24.
	AddressKindPrefix
	// AddressKindRange is an inclusive range of addresses.
	AddressKindRange
	// AddressKindFQDN is a domain name, possibly with a leading wildcard.
	// It cannot be resolved offline and makes the owning rule undecidable.
	AddressKindFQDN
)

// String returns the kind name.
func (k AddressKind) String() string {
	switch k {
	case AddressKindUnset:
		return "unset"
	case AddressKindPrefix:
		return "prefix"
	case AddressKindRange:
		return "range"
	case AddressKindFQDN:
		return "fqdn"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (k AddressKind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// AddressEntry is one member of an address object.
type AddressEntry struct {
	Kind   AddressKind  `json:"kind"`
	Prefix netip.Prefix `json:"prefix,omitzero"`
	From   netip.Addr   `json:"from,omitzero"`
	To     netip.Addr   `json:"to,omitzero"`
	FQDN   string       `json:"fqdn,omitempty"`
	// VirtualRouter is the routing context the device resolves FQDN in
	// (StoneOS host "name" vrouter "vr"); empty means the default.
	VirtualRouter string `json:"virtual_router,omitempty"`
	// Exclude removes the entry from the object instead of adding it.
	Exclude bool `json:"exclude,omitempty"`
}

// PrefixEntry returns an entry for a host or subnet. The prefix is masked.
func PrefixEntry(p netip.Prefix) AddressEntry {
	return AddressEntry{Kind: AddressKindPrefix, Prefix: p.Masked()}
}

// HostEntry returns an entry for a single address.
func HostEntry(a netip.Addr) AddressEntry {
	return PrefixEntry(netip.PrefixFrom(a, a.BitLen()))
}

// RangeEntry returns an entry for the inclusive range from..to.
func RangeEntry(from, to netip.Addr) AddressEntry {
	return AddressEntry{Kind: AddressKindRange, From: from, To: to}
}

// FQDNEntry returns an entry for a domain name.
func FQDNEntry(name string) AddressEntry { return AddressEntry{Kind: AddressKindFQDN, FQDN: name} }

// Set returns the addresses of the entry. It reports false for FQDN entries
// and for entries that are not valid, which cannot be resolved offline.
func (e AddressEntry) Set() (traffic.AddressSet, bool) {
	switch e.Kind {
	case AddressKindPrefix:
		if !e.Prefix.IsValid() {
			return traffic.AddressSet{}, false
		}
		return traffic.NewAddressSet(e.Prefix), true
	case AddressKindRange:
		s := traffic.AddressRange(e.From, e.To)
		return s, !s.IsEmpty()
	case AddressKindUnset, AddressKindFQDN:
		return traffic.AddressSet{}, false
	default:
		return traffic.AddressSet{}, false
	}
}

// String writes the entry as an address, prefix, range or domain name.
func (e AddressEntry) String() string {
	prefix := ""
	if e.Exclude {
		prefix = "!"
	}
	switch e.Kind {
	case AddressKindPrefix:
		if e.Prefix.IsSingleIP() {
			return prefix + e.Prefix.Addr().String()
		}
		return prefix + e.Prefix.String()
	case AddressKindRange:
		return prefix + e.From.String() + "-" + e.To.String()
	case AddressKindFQDN:
		return prefix + e.FQDN
	case AddressKindUnset:
		return prefix + "unset"
	default:
		return prefix + "invalid"
	}
}

// Address is a named address object: hosts, subnets, ranges and domain
// names, optionally minus excluded entries.
type Address struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Entries     []AddressEntry `json:"entries"`
	// Predefined marks objects built into the operating system rather than
	// declared in the configuration.
	Predefined bool `json:"predefined,omitempty"`
	// Invalid keeps entries the parser could not read; an object with
	// invalid entries cannot be resolved exactly.
	Invalid []string `json:"invalid,omitempty"`
}

// AddressGroup is a named collection of address objects and groups. On
// Hillstone, where any address object may contain members, inline entries
// declared next to the members are kept in Entries.
type AddressGroup struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Members     []string       `json:"members,omitempty"`
	Entries     []AddressEntry `json:"entries,omitempty"`
	// Filter is the tag expression of a dynamic group. Dynamic membership
	// cannot be resolved offline.
	Filter     string `json:"filter,omitempty"`
	Predefined bool   `json:"predefined,omitempty"`
	// Invalid keeps inline entries the parser could not read.
	Invalid []string `json:"invalid,omitempty"`
}

// AddressRef is an address operand of a rule: either the name of an
// address object or group, or an inline entry.
type AddressRef struct {
	Name  string       `json:"name,omitempty"`
	Entry AddressEntry `json:"entry,omitzero"`
}

// NamedAddress refers to an address object or group by name.
func NamedAddress(name string) AddressRef { return AddressRef{Name: name} }

// InlineAddress uses an entry directly.
func InlineAddress(e AddressEntry) AddressRef { return AddressRef{Entry: e} }

// IsInline reports whether the reference carries its own entry.
func (r AddressRef) IsInline() bool { return r.Name == "" }

// String writes the object name or the inline entry.
func (r AddressRef) String() string {
	if r.IsInline() {
		return r.Entry.String()
	}
	return r.Name
}

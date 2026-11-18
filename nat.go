package firemon

// NATKind tells which address a dynamic NAT rule rewrites.
type NATKind uint8

// NAT kinds.
const (
	NATKindUnset NATKind = iota
	// NATKindSource rewrites the source address (SNAT).
	NATKindSource
	// NATKindDestination rewrites the destination address (DNAT).
	NATKindDestination
)

// String returns "source", "destination" or "unset".
func (k NATKind) String() string {
	switch k {
	case NATKindUnset:
		return "unset"
	case NATKindSource:
		return "source"
	case NATKindDestination:
		return "destination"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (k NATKind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// TranslationMode tells how a NAT rule chooses the translated address.
type TranslationMode uint8

// Translation modes.
const (
	TranslationModeUnset TranslationMode = iota
	// TranslationModeNone leaves the address unchanged (no-NAT exemption).
	TranslationModeNone
	// TranslationModeAddress translates to the addresses in Translation.Addresses.
	TranslationModeAddress
	// TranslationModeInterface translates to the egress interface address.
	TranslationModeInterface
)

// String returns the mode name.
func (m TranslationMode) String() string {
	switch m {
	case TranslationModeUnset:
		return "unset"
	case TranslationModeNone:
		return "none"
	case TranslationModeAddress:
		return "address"
	case TranslationModeInterface:
		return "interface"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (m TranslationMode) MarshalText() ([]byte, error) { return []byte(m.String()), nil }

// Translation describes the rewritten side of a NAT rule.
type Translation struct {
	Mode      TranslationMode `json:"mode"`
	Addresses []AddressRef    `json:"addresses,omitempty"`
	Interface string          `json:"interface,omitempty"`
	// Port is the translated destination port; zero keeps the original.
	Port uint16 `json:"port,omitempty"`
	// PortTranslation reports source port rewriting (PAT, dynamic-ip-and-port).
	PortTranslation bool `json:"port_translation,omitempty"`
}

// DynamicNAT is an ordered NAT rule (Hillstone snatrule and dnatrule,
// PAN-OS NAT rulebase). It may translate the source, the destination or
// both; a rule whose translations are TranslationModeNone exempts traffic
// from later NAT rules. Empty lists mean "any".
type DynamicNAT struct {
	ID            string       `json:"id"`
	Name          string       `json:"name,omitempty"`
	Description   string       `json:"description,omitempty"`
	VirtualRouter string       `json:"virtual_router,omitempty"`
	From          []string     `json:"from,omitempty"`
	To            []string     `json:"to,omitempty"`
	Egress        string       `json:"egress,omitempty"`
	Source        []AddressRef `json:"source,omitempty"`
	Destination   []AddressRef `json:"destination,omitempty"`
	Services      []string     `json:"services,omitempty"`
	// TranslatedSource and TranslatedDestination describe the rewritten
	// sides; TranslationModeUnset leaves that side to other rules.
	TranslatedSource      Translation `json:"translated_source,omitzero"`
	TranslatedDestination Translation `json:"translated_destination,omitzero"`
	Disabled              bool        `json:"disabled,omitempty"`
	// Precedence orders the rule among all NAT entries, static mappings
	// included, on vendors with one NAT rulebase (Semantics.NATOrder).
	Precedence int `json:"precedence,omitempty"`
}

// StaticNAT is a one-to-one bidirectional mapping between real (internal)
// and mapped (public) addresses (Hillstone bnatrule, PAN-OS static-ip
// bi-directional). Both sides must hold the same number of addresses.
// Outbound traffic from Real gets the Mapped source; inbound traffic to
// Mapped gets the Real destination.
type StaticNAT struct {
	ID            string     `json:"id"`
	Name          string     `json:"name,omitempty"`
	VirtualRouter string     `json:"virtual_router,omitempty"`
	Real          AddressRef `json:"real"`
	Mapped        AddressRef `json:"mapped"`
	// From restricts the zones outbound traffic comes from; empty means any.
	From []string `json:"from,omitempty"`
	// Zones restricts where the mapped address is visible: the egress zone
	// of outbound traffic and the ingress zone of inbound traffic.
	Zones      []string `json:"zones,omitempty"`
	Disabled   bool     `json:"disabled,omitempty"`
	Precedence int      `json:"precedence,omitempty"`
	// InboundOnly marks the reverse half of a rule whose outbound half is a
	// DynamicNAT (PAN-OS bi-directional static-ip).
	InboundOnly bool `json:"inbound_only,omitempty"`
}

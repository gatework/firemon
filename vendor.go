package firemon

import (
	"fmt"
	"strings"
)

// Vendor identifies the firewall operating system that produced a Config.
type Vendor uint8

// Supported vendors.
const (
	VendorUnset Vendor = iota
	// VendorHillstone is Hillstone StoneOS.
	VendorHillstone
	// VendorPaloAlto is Palo Alto Networks PAN-OS.
	VendorPaloAlto
)

// ParseVendor accepts "hillstone" or "paloalto", ignoring case.
func ParseVendor(text string) (Vendor, error) {
	switch strings.ToLower(text) {
	case "hillstone", "stoneos":
		return VendorHillstone, nil
	case "paloalto", "panos", "pan-os":
		return VendorPaloAlto, nil
	default:
		return VendorUnset, fmt.Errorf("firemon: unknown vendor %q", text)
	}
}

// String returns the vendor keyword accepted by ParseVendor.
func (v Vendor) String() string {
	switch v {
	case VendorUnset:
		return "unset"
	case VendorHillstone:
		return "hillstone"
	case VendorPaloAlto:
		return "paloalto"
	default:
		return "invalid"
	}
}

// Valid reports whether v is a supported vendor.
func (v Vendor) Valid() bool { return v == VendorHillstone || v == VendorPaloAlto }

// MarshalText implements encoding.TextMarshaler.
func (v Vendor) MarshalText() ([]byte, error) {
	if !v.Valid() {
		return nil, fmt.Errorf("firemon: cannot marshal vendor %d", uint8(v))
	}
	return []byte(v.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (v *Vendor) UnmarshalText(text []byte) error {
	parsed, err := ParseVendor(string(text))
	if err != nil {
		return err
	}
	*v = parsed
	return nil
}

// AddressStage tells which form of a translated address a security rule
// matches.
type AddressStage uint8

// Address stages.
const (
	AddressStageUnset AddressStage = iota
	// AddressStageOriginal matches the address before NAT.
	AddressStageOriginal
	// AddressStageTranslated matches the address after NAT.
	AddressStageTranslated
)

// MarshalText implements encoding.TextMarshaler.
func (s AddressStage) MarshalText() ([]byte, error) {
	if s > AddressStageTranslated {
		return nil, fmt.Errorf("firemon: invalid address stage %d", uint8(s))
	}
	return []byte(s.String()), nil
}

// NATOrder tells how NAT rules are ordered and applied.
type NATOrder uint8

// NAT orders.
const (
	NATOrderUnset NATOrder = iota
	// NATOrderSeparate applies destination NAT before routing and source NAT
	// after the policy, each from its own ordered list (Hillstone).
	NATOrderSeparate
	// NATOrderSingle applies the first matching rule of one list, which
	// decides both translations, matching the original packet and the
	// pre-NAT zones (PAN-OS).
	NATOrderSingle
)

// String returns the order name.
func (o NATOrder) String() string {
	switch o {
	case NATOrderUnset:
		return "unset"
	case NATOrderSeparate:
		return "separate"
	case NATOrderSingle:
		return "single"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (o NATOrder) MarshalText() ([]byte, error) { return []byte(o.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (o *NATOrder) UnmarshalText(text []byte) error {
	return unmarshalEnum(o, text, "NAT order", NATOrderUnset, NATOrderSeparate, NATOrderSingle)
}

// Semantics records the vendor behaviour policy evaluation depends on. The
// vendor parser fills it in; the query engine never switches on Vendor.
type Semantics struct {
	// PolicyDestination is the destination address form security rules
	// match when destination NAT applies. Zones are always derived from the
	// translated destination.
	PolicyDestination AddressStage `json:"policy_destination"`
	// IntrazoneAction applies to traffic that enters and leaves the same zone
	// and matches no rule.
	IntrazoneAction Action `json:"intrazone_action"`
	// InterzoneAction applies to traffic between different zones that
	// matches no rule.
	InterzoneAction Action `json:"interzone_action"`
	// DefaultVirtualRouter is the routing context used when a request does
	// not name one.
	DefaultVirtualRouter string `json:"default_virtual_router,omitempty"`
	// NATOrder selects how NAT rules apply; unset behaves as separate.
	NATOrder NATOrder `json:"nat_order,omitempty"`
	// StaticNATFirst applies static mappings before dynamic destination NAT
	// on separate-order vendors.
	StaticNATFirst bool `json:"static_nat_first,omitempty"`
	// NumericRuleIDs reports that rule IDs are device-assigned numbers
	// (Hillstone) rather than rule names (PAN-OS).
	NumericRuleIDs bool `json:"numeric_rule_ids,omitempty"`
}

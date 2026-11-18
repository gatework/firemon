package firemon

import "fmt"

// unmarshalEnum sets *dst to the value among values whose String form is
// text, rejecting unknown names (OOP-7).
func unmarshalEnum[T interface {
	comparable
	fmt.Stringer
}](dst *T, text []byte, kind string, values ...T) error {
	for _, v := range values {
		if v.String() == string(text) {
			*dst = v
			return nil
		}
	}
	return fmt.Errorf("firemon: unknown %s %q", kind, text)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (a *Action) UnmarshalText(text []byte) error {
	return unmarshalEnum(a, text, "action", ActionUnset, ActionPermit, ActionDeny)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (m *ZoneMode) UnmarshalText(text []byte) error {
	return unmarshalEnum(m, text, "zone mode", ZoneModeUnset, ZoneModeLayer3, ZoneModeLayer2, ZoneModeTap, ZoneModeTunnel)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *AddressKind) UnmarshalText(text []byte) error {
	return unmarshalEnum(k, text, "address kind", AddressKindUnset, AddressKindPrefix, AddressKindRange, AddressKindFQDN)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *NATKind) UnmarshalText(text []byte) error {
	return unmarshalEnum(k, text, "NAT kind", NATKindUnset, NATKindSource, NATKindDestination)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (m *TranslationMode) UnmarshalText(text []byte) error {
	return unmarshalEnum(m, text, "translation mode", TranslationModeUnset, TranslationModeNone, TranslationModeAddress, TranslationModeInterface)
}

// String returns "unset", "original" or "translated".
func (s AddressStage) String() string {
	switch s {
	case AddressStageUnset:
		return "unset"
	case AddressStageOriginal:
		return "original"
	case AddressStageTranslated:
		return "translated"
	default:
		return "invalid"
	}
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *AddressStage) UnmarshalText(text []byte) error {
	return unmarshalEnum(s, text, "address stage", AddressStageUnset, AddressStageOriginal, AddressStageTranslated)
}

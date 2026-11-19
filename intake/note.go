package intake

// Code classifies a note.
type Code uint8

// Note codes.
const (
	CodeUnset Code = iota
	// CodeMasked: a prefix had host bits set; they were cleared.
	CodeMasked
	// CodeMask: an address and dotted mask became a prefix.
	CodeMask
	// CodeShortRange: a shortened range ("10.1.1.1-9") was expanded.
	CodeShortRange
	// CodeWildcard: an octet wildcard ("10.1.1.*") became a prefix.
	CodeWildcard
	// CodeDomain: a domain name is matched against domain-based rules.
	CodeDomain
	// CodeDefaultTCP: a bare port was taken as TCP.
	CodeDefaultTCP
	// CodeInheritedProtocol: a bare port took the protocol of the item before it.
	CodeInheritedProtocol
	// CodeServiceName: a service name was looked up in the service book.
	CodeServiceName
	// CodeApplication: a name was taken as an application.
	CodeApplication
	// CodeDuplicate: an item repeated or was covered by another item.
	CodeDuplicate
	// CodeInvalid: an item could not be read and was skipped.
	CodeInvalid
	// CodeUnsupported: an item was read but cannot be used on this side.
	CodeUnsupported
	// CodeUnknownApplication: an application no configuration or
	// application book knows.
	CodeUnknownApplication
)

// String returns the code name used in JSON output.
func (c Code) String() string {
	names := [...]string{"unset", "masked", "mask", "short-range", "wildcard", "domain", "default-tcp",
		"inherited-protocol", "service-name", "application", "duplicate", "invalid", "unsupported", "unknown-application"}
	if int(c) < len(names) {
		return names[c]
	}
	return "invalid-code"
}

// MarshalText implements encoding.TextMarshaler.
func (c Code) MarshalText() ([]byte, error) { return []byte(c.String()), nil }

// Field names the input a note is about.
type Field string

// Input fields.
const (
	FieldSource      Field = "source"
	FieldDestination Field = "destination"
	FieldService     Field = "service"
)

// Note reports how one input item was understood.
type Note struct {
	Field Field  `json:"field"`
	Code  Code   `json:"code"`
	Input string `json:"input"`
	// Result is the canonical form the item became, when it was used.
	Result string `json:"result,omitempty"`
}

// Skipped reports whether the item was not used.
func (n Note) Skipped() bool {
	return n.Code == CodeInvalid || n.Code == CodeUnsupported || n.Code == CodeDuplicate
}

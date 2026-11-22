package firemon

// HARole is a firewall's runtime role in its HA cluster, as the device
// reports it.
type HARole string

// HA roles. Unknown means the device did not say: no HA, an initializing
// or failed member, or output the vendor reader does not recognize.
const (
	HARoleUnknown HARole = ""
	HARoleActive  HARole = "active"
	HARoleStandby HARole = "standby"
)

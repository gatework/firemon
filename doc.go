// Package firemon models a firewall in network-operations terms and compiles
// it into an evaluable policy.
//
// Two layers keep syntax and semantics apart:
//
//   - [Config] is the declarative device configuration a vendor parser
//     produces: zones, interfaces, virtual routers, static routes, address
//     objects and groups, service objects and groups, schedules, security
//     rules, static NAT and dynamic (source and destination) NAT. Every
//     reference is by name, exactly as the device stores it. Config is plain
//     data: it marshals to JSON for golden tests and design changes edit it.
//   - [Firewall] is the result of [Compile]: names resolved to exact
//     [traffic] sets, rules ordered with their match spaces precomputed,
//     routing tables sorted for longest-prefix lookup, and every construct
//     that cannot be evaluated recorded as an [Issue] instead of being
//     widened to "any".
//
// The package performs no I/O. Vendor syntax lives in vendors/*, policy
// evaluation in query, change design in design.
package firemon

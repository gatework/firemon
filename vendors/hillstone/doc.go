// Package hillstone parses Hillstone StoneOS running configurations into
// firemon.Config and renders design plans as StoneOS CLI commands.
//
// StoneOS output is a sequence of top-level blocks: a head line at column
// zero ("address \"web\"", "rule id 13", "ip vrouter \"trust-vr\""), indented
// body lines, and a closing "exit" at column zero. Objects are often
// declared twice: an empty forward declaration near the top and the full
// definition later; the parser merges both. Lines inside policy-relevant
// blocks that the parser does not recognize are reported as diagnostics;
// sections unrelated to policy evaluation (IPS, AV, PKI, administrators)
// are skipped as a whole.
package hillstone

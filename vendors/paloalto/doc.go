// Package paloalto parses PAN-OS configurations in set format ("show
// config running" with "set cli config-output-format set") into
// firemon.Config and renders design plans as PAN-OS set commands.
//
// Every statement is one "set" path with a value; a rule's attributes are
// spread over many statements. The parser collects statements first and
// builds the configuration second, so rule operands can be classified as
// object names or inline addresses once every object is known. Rule order
// is the order in which each rule name first appears. Objects under
// "shared" and under the single "vsys" are merged into one namespace;
// device-group and multi-vsys configurations are reported as diagnostics.
package paloalto

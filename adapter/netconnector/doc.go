// Package netconnector connects firemon to devices through
// github.com/gatework/net-connector.
//
// A Client reads running configurations and lends deployment sessions for
// one Hillstone or PAN-OS device. Hillstone commands are sent one at a time
// and saved after verification; PAN-OS set commands are collected until
// CommitCommand and committed as one candidate batch, which is also the
// persistence step. Dialogues and success evidence belong to the
// net-connector drivers.
package netconnector

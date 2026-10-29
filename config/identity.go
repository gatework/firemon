package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	fm "github.com/gatework/firemon"
)

// RouteID assigns identity to an unnamed native route from its declaration,
// never its line number. Named routes keep their native identity instead.
func RouteID(r fm.RouteRecord) fm.ID {
	value := struct {
		Scope, Destination, NextHop, Interface string
		Metric                                 uint32
		Direct                                 bool
	}{r.Scope, r.Destination.String(), r.NextHop.String(), string(r.Interface), r.Metric, r.Direct}
	// This fixed value contains only strings, integers and a boolean.
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return fm.ID("route:" + hex.EncodeToString(sum[:]))
}

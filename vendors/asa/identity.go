package asa

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
)

func declarationID(prefix string, words []string) fm.ID {
	// A slice of strings always has a JSON representation. Length-delimited
	// encoding also distinguishes quoted words containing whitespace/separators.
	b, _ := json.Marshal(words)
	h := sha256.Sum256(b)
	return fm.ID(prefix + hex.EncodeToString(h[:]))
}

func inlineService(d *fm.Data, prior *config.Builder, terms []fm.ServiceTerm) fm.ID {
	words := make([]string, 0, len(terms)*10)
	for _, t := range terms {
		for _, r := range []flow.Interval{t.Protocol, t.SourcePort, t.DestinationPort, t.ICMPType, t.ICMPCode} {
			words = append(words, strconv.Itoa(int(r.Low)), strconv.Itoa(int(r.High)))
		}
	}
	id := declarationID("$service:", words)
	if prior.HasService(id) {
		return id
	}
	for _, row := range d.Services {
		if row.ID == id {
			return id
		}
	}
	d.Services = append(d.Services, fm.ServiceRecord{Object: fm.Object{ID: id}, Terms: terms})
	return id
}

// ACLDeclarationID binds the complete tokenized native ACL declaration. Line
// numbers, hit counters and expanded operational rows are not declaration identity.
func ACLDeclarationID(words []string) fm.ID { return declarationID("acl:", words) }

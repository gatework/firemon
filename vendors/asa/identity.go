package asa

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

func declarationID(prefix string, words []string) fm.ID {
	// A slice of strings always has a JSON representation. Length-delimited
	// encoding also distinguishes quoted words containing whitespace/separators.
	b, _ := json.Marshal(words)
	h := sha256.Sum256(b)
	return fm.ID(prefix + hex.EncodeToString(h[:]))
}

func inlineService(d *fm.Data, prior fm.Data, terms []fm.ServiceTerm) fm.ID {
	words := make([]string, 0, len(terms)*10)
	for _, t := range terms {
		for _, r := range []flow.Interval{t.Protocol, t.SourcePort, t.DestinationPort, t.ICMPType, t.ICMPCode} {
			words = append(words, strconv.Itoa(int(r.Low)), strconv.Itoa(int(r.High)))
		}
	}
	id := declarationID("$service:", words)
	for _, rows := range [][]fm.ServiceRecord{prior.Services, d.Services} {
		for _, row := range rows {
			if row.ID == id {
				return id
			}
		}
	}
	d.Services = append(d.Services, fm.ServiceRecord{Object: fm.Object{ID: id}, Terms: terms})
	return id
}

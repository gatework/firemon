package hillstone

import (
	"github.com/gatework/firemon"
)

// qosEngine records the objects QoS pipes refer to. The model does not
// evaluate QoS, but the objects stay in use:
//
//	qos-engine first
//	  root-pipe "NAME" id N
//	    schedule "S"
//	    pipe-map id M
//	      src-addr "A" | dst-addr "A" | service "S"
//	    exit
//	  exit
//	exit
func (s *state) qosEngine(b block) {
	pipe := ""
	for _, l := range b.body {
		w := newWords(l.Text)
		switch kw := w.next(); kw {
		case "root-pipe", "pipe":
			pipe = w.next()
		case "schedule":
			s.externalUse(pipe, firemon.ObjectKindSchedule, w.next())
		case "src-addr", "dst-addr":
			s.externalUse(pipe, firemon.ObjectKindAddress, w.next())
		case "service":
			s.externalUse(pipe, firemon.ObjectKindService, w.next())
		}
	}
}

func (s *state) externalUse(id string, kind firemon.ObjectKind, name string) {
	if name == "" || name == anyName {
		return
	}
	s.cfg.ExternalUses = append(s.cfg.ExternalUses, firemon.ExternalUse{Site: firemon.UseSiteQoS, ID: "qos " + id, Kind: kind, Name: name})
}

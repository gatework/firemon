package hillstone

import (
	"slices"
	"strings"

	"github.com/gatework/firemon/config"
	text "github.com/gatework/parser"
)

// scanner uses StoneOS command contexts. Export indentation additionally fences
// unfamiliar nested blocks, without assigning their children domain semantics.
type scanner struct {
	lines   []text.Line
	indents []int
}

func (s *scanner) nested(line config.Statement) bool {
	indent := indentation(line.Raw)
	for _, next := range s.lines[line.Span.Last:] {
		text := strings.TrimSpace(next.Text)
		if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, "!") {
			continue
		}
		return indentation(next.Raw) > indent
	}
	return false
}

func (s *scanner) emptyBlock(line config.Statement) bool {
	for _, next := range s.lines[line.Span.Last:] {
		text := strings.TrimSpace(next.Text)
		if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, "!") {
			continue
		}
		return text == "exit" && indentation(next.Raw) == indentation(line.Raw)
	}
	return false
}

func indentation(raw string) int {
	n := 0
	for _, c := range raw {
		switch c {
		case ' ':
			n++
		case '\t':
			n += 8 - n%8
		default:
			return n
		}
	}
	return n
}

func (scan *scanner) classify(s config.Statement, path []string) (config.Boundary, string) {
	boundary, kind := scan.boundary(s, path)
	switch boundary {
	case config.OpenBlock:
		scan.indents = append(scan.indents, indentation(s.Raw))
	case config.CloseBlock:
		if len(scan.indents) > 0 {
			scan.indents = scan.indents[:len(scan.indents)-1]
		}
	}
	return boundary, kind
}

func (s *scanner) opens(line config.Statement) bool {
	if s.nested(line) {
		return true
	}
	// A same-indent exit closes an empty child only when the child is deeper
	// than its parent. Unindented members still belong to their native context.
	deeper := len(s.indents) == 0 || indentation(line.Raw) > s.indents[len(s.indents)-1]
	return deeper && s.emptyBlock(line)
}

func (scan *scanner) boundary(s config.Statement, path []string) (config.Boundary, string) {
	w := s.Words
	if len(w) == 0 || strings.HasPrefix(w[0], "#") || strings.HasPrefix(w[0], "!") || w[0] == "hostname" {
		return config.Member, ""
	}
	if len(w) == 1 && w[0] == "exit" {
		return config.CloseBlock, ""
	}
	owner := ""
	if len(path) > 0 {
		owner = path[len(path)-1]
	}
	// Tunnel interface bindings and domain routes are scalar members. Some
	// exports indent domain-route more deeply without entering another context.
	if owner == "tunnel" && (w[0] == "interface" || w[0] == "domain-route") {
		return config.Member, ""
	}
	if owner == "outside" || owner == "unknown" || owner == "qos" {
		if owner == "qos" && (w[0] == "root-pipe" || w[0] == "pipe") {
			return config.OpenBlock, "qos"
		}
		if scan.opens(s) {
			return config.OpenBlock, "unknown"
		}
		return config.Member, ""
	}
	if owner != "" && owner != "vrf" && owner != "policy" && owner != "policy-global" {
		if owner == "pbr-policy" && w[0] == "match" {
			return config.OpenBlock, "pbr-match"
		}
		if scan.opens(s) {
			return config.OpenBlock, "unknown"
		}
		return config.Member, ""
	}
	switch w[0] {
	case "zone", "interface", "address", "service", "servgroup", "schedule", "rule", "natpool", "pbr-policy":
		return config.OpenBlock, w[0]
	case "policy-global":
		return config.OpenBlock, "policy-global"
	case "policy":
		if len(w) > 1 && w[1] == "from" {
			return config.OpenBlock, "policy"
		}
	case "ip":
		if len(w) > 1 && w[1] == "vrouter" {
			return config.OpenBlock, "vrf"
		}
	case "admin":
		if len(w) == 3 && w[1] == "user" {
			return config.OpenBlock, "outside"
		}
	case "aaa-server", "role":
		if len(w) == 2 {
			return config.OpenBlock, "outside"
		}
	case "qos-engine":
		return config.OpenBlock, "qos"
	case "tunnel":
		if len(w) >= 3 {
			return config.OpenBlock, "tunnel"
		}
	case "track", "interface-group", "webauth", "vswitch":
		if len(w) == 2 {
			return config.OpenBlock, "unknown"
		}
	}
	if strings.HasSuffix(w[0], "-profile") && len(w) == 2 {
		return config.OpenBlock, "unknown"
	}
	if scan.opens(s) {
		return config.OpenBlock, "unknown"
	}
	return config.Member, ""
}

func namedHeader(w []string) bool {
	return len(w) == 2 && strings.TrimSpace(w[1]) != ""
}

func definitionHeader(w []string) bool {
	if namedHeader(w) {
		return true
	}
	if len(w) < 3 || w[1] == "" {
		return false
	}
	switch w[0] {
	case "zone":
		return len(w) == 3 && w[2] == "l2"
	case "interface":
		return len(w) == 3 && w[2] == "local"
	case "address":
		return slices.Equal(w[2:], []string{"predefined"}) || slices.Equal(w[2:], []string{"ipv6"}) || slices.Equal(w[2:], []string{"ipv6", "predefined"})
	}
	return false
}

// Structural scanning keeps malformed wrappers scoped. Interpretation and
// source claims must both accept the complete native header before entering it.
func contextHeader(b *config.Block) bool {
	w := b.Header.Words
	switch b.Kind {
	case "vrf":
		return len(w) == 3 && strings.TrimSpace(w[2]) != ""
	case "policy":
		return len(w) == 5 && w[1] == "from" && w[3] == "to" && strings.TrimSpace(w[2]) != "" && strings.TrimSpace(w[4]) != ""
	case "policy-global":
		return len(w) == 1
	}
	return false
}

func ruleHeader(w []string) bool {
	if len(w) == 3 && w[1] == "id" {
		return strings.TrimSpace(w[2]) != ""
	}
	return namedHeader(w) && w[1] != "id"
}

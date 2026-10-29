package asa

import (
	"testing"

	fm "github.com/gatework/firemon"
)

func TestLiteralIdentityIncludesCommittedAndCurrentDraft(t *testing.T) {
	p := &parser{}
	d := fm.Data{}
	first, _, ok := p.operand([]string{"host", "192.0.2.1"}, &d)
	if !ok {
		t.Fatal("literal")
	}
	again, _, ok := p.operand([]string{"192.0.2.1", "255.255.255.255"}, &d)
	if !ok || first != again || len(d.Addresses) != 1 {
		t.Fatal("draft literal duplicated")
	}
	p.data = d
	next := fm.Data{}
	again, _, ok = p.operand([]string{"host", "192.0.2.1"}, &next)
	if !ok || first != again || len(next.Addresses) != 0 {
		t.Fatal("committed literal duplicated")
	}
	discarded := fm.Data{}
	p.operand([]string{"host", "192.0.2.2"}, &discarded)
	replacement := fm.Data{}
	p.operand([]string{"host", "192.0.2.2"}, &replacement)
	if len(replacement.Addresses) != 1 {
		t.Fatal("uncommitted identity leaked")
	}
}

package firemon_test

import (
	"fmt"
	"runtime/debug"
	"slices"
	"testing"

	fm "github.com/gatework/firemon"
)

func TestGroupCyclesAreReportedOnceAtTheirReentryGroup(t *testing.T) {
	member := func(id fm.ID) fm.AddressRef { return fm.AddressRef{Kind: fm.AddressGroupObject, ID: id} }
	d := fm.Data{
		Metadata: fm.Metadata{Device: "synthetic", Vendor: "huawei"},
		AddressGroups: []fm.AddressGroupRecord{
			{Object: fm.Object{ID: "outer"}, Members: []fm.AddressRef{member("inner")}},
			{Object: fm.Object{ID: "inner"}, Members: []fm.AddressRef{member("outer")}},
			{Object: fm.Object{ID: "acyclic"}, Members: []fm.AddressRef{member("inner")}},
		},
		ServiceGroups: []fm.ServiceGroupRecord{
			{Object: fm.Object{ID: "self"}, Members: []fm.ServiceRef{{Kind: fm.ServiceGroupObject, ID: "self"}}},
		},
	}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	var got []fm.Diagnostic
	for _, diagnostic := range fw.Diagnostics() {
		if diagnostic.Code == "group-cycle" {
			got = append(got, diagnostic)
		}
	}
	expected := []fm.Diagnostic{
		{Code: "group-cycle", Object: "outer", Message: "cyclic address group"},
		{Code: "group-cycle", Object: "self", Message: "cyclic service group"},
	}
	if !slices.Equal(got, expected) {
		t.Fatalf("got %+v, expected %+v", got, expected)
	}
	if fw.Complete() {
		t.Fatal("cyclic groups must leave the graph incomplete")
	}
}

// Nesting depth is attacker-controlled through snapshots and captures, so the
// cycle walk must not grow the goroutine stack with it: exceeding the stack
// limit is a fatal error that no caller can recover from.
func TestDeepGroupNestingDoesNotGrowTheStack(t *testing.T) {
	const depth = 200_000
	defer debug.SetMaxStack(debug.SetMaxStack(4 << 20))
	d := fm.Data{Metadata: fm.Metadata{Device: "synthetic", Vendor: "huawei"}}
	for i := range depth {
		next := fm.ID(fmt.Sprint((i + 1) % depth))
		d.AddressGroups = append(d.AddressGroups, fm.AddressGroupRecord{
			Object:  fm.Object{ID: fm.ID(fmt.Sprint(i))},
			Members: []fm.AddressRef{{Kind: fm.AddressGroupObject, ID: next}},
		})
	}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	expected := []fm.Diagnostic{{Code: "group-cycle", Object: "0", Message: "cyclic address group"}}
	if got := fw.Diagnostics(); !slices.Equal(got, expected) {
		t.Fatalf("got %d diagnostics %v, expected %v", len(got), got[:min(len(got), 3)], expected)
	}
}

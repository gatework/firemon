package firemon_test

import (
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

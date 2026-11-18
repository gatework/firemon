package yamlfile_test

import (
	"testing"

	"github.com/gatework/firemon/adapter/yamlfile"
)

func TestParse(t *testing.T) {
	t.Parallel()
	f, err := yamlfile.Parse([]byte(`
firewalls:
  - name: fw1
    cluster: site
    protected:
      - zone: lan
        networks: [10.1.0.0/16, 10.9.9.9]
        exclude: [10.1.255.0/24]
  - name: fw2
    cluster: site
    snapshot: fw2-latest
`))
	if err != nil {
		t.Fatal(err)
	}
	ps, err := f.Protections(t.Context())
	if err != nil || len(ps) != 1 || len(ps[0].Networks) != 2 || ps[0].Networks[1].Bits() != 32 || ps[0].Zone != "lan" {
		t.Fatalf("protections %+v %v", ps, err)
	}
	if f.Firewalls[0].SnapshotOf() != "fw1" || f.Firewalls[1].SnapshotOf() != "fw2-latest" {
		t.Fatal("snapshot names")
	}
}

func TestParse_Rejects(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"firewalls:\n  - name: a\n    protectd: []\n",
		"firewalls:\n  - name: a\n  - name: a\n",
		"firewalls:\n  - name: a\n    protected:\n      - networks: [10.0.0.300/8]\n",
		"firewalls:\n  - cluster: x\n",
	} {
		if _, err := yamlfile.Parse([]byte(in)); err == nil {
			t.Errorf("want error for %q", in)
		}
	}
}

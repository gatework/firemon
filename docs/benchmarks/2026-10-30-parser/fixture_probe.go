//go:build ignore

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/vendors"
	"os"
)

func main() {
	for _, v := range []struct{ name, path string }{
		{"hillstone", "vendors/hillstone/testdata/basic.cfg"},
		{"asa", "vendors/asa/testdata/basic.cfg"},
		{"fortinet", "vendors/fortinet/testdata/basic.conf"},
		{"huawei", "/tmp/firemon-parser-20261030/huawei.conf"},
		{"netscreen", "vendors/netscreen/testdata/basic.set"},
		{"paloalto", "vendors/paloalto/testdata/basic.cfg"},
		{"srx", "vendors/srx/testdata/basic.set"},
	} {
		raw, err := os.ReadFile(v.path)
		if err != nil {
			panic(err)
		}
		fw, err := (vendors.Parser{}).Parse(context.Background(), config.Source{Text: string(raw), Complete: true}, fm.Metadata{Device: "synthetic", Vendor: v.name})
		if err != nil {
			panic(err)
		}
		d := fw.Export()
		d.Metadata.ParserVersion = "comparison"
		b, err := json.Marshal(d)
		if err != nil {
			panic(err)
		}
		checked, err := fm.Seal(d)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s export=%x semantic=%s complete=%v\n", v.name, sha256.Sum256(b), checked.SemanticDigest(), fw.Complete())
	}
}

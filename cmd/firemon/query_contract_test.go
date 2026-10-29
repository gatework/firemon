package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestQueryJSONDomainNameCompatibility(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "synthetic.cfg")
	raw := "policy-global\nrule id 1\nsrc-addr any\ndst-addr any\nservice any\naction permit\nexit\nexit\n"
	if err := os.WriteFile(input, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"import", "--store", dir, "--device", "synthetic", "--vendor", "hillstone", "--file", input, "--complete", "--publication", "one"}, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"query", "--store", dir, "--device", "synthetic", "--source", "192.0.2.1/32", "--destination", "198.51.100.1/32", "--service", "tcp/443"}, &out); err != nil {
		t.Fatal(err)
	}
	const expected = `{"complete":true,"coverage":{"allowed":[{"Source":{"First":"192.0.2.1","Last":"192.0.2.1"},"Destination":{"First":"198.51.100.1","Last":"198.51.100.1"},"Protocol":{"Low":6,"High":6},"SourcePort":{"Low":0,"High":65535},"DestinationPort":{"Low":443,"High":443},"ICMPType":{"Low":0,"High":255},"ICMPCode":{"Low":0,"High":255}}],"denied":null,"unknown":null,"unmatched":null}}`
	var got, want any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(expected), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("query JSON changed: %s", out.String())
	}
}

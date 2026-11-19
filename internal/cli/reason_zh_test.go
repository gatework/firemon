package cli

import (
	"regexp"
	"testing"
)

func TestZhReason(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"application match MySQL": "按应用匹配（MySQL）",
		"incomplete, never matches: no action, source, destination, service":               "策略不完整，永不命中：缺少动作、源、目的、服务",
		`unresolvable fqdn "a.example.com" in "web"`:                                       "域名 a.example.com（对象 web）无法离线解析",
		"criterion not translated: vlan-id 2008; rule group G not carried over":            "条件未翻译：按 VLAN 2008 匹配；策略组 G 未迁移",
		"WhiteList: wildcard domain names have no address object form; use a URL category": "WhiteList：通配域名无法写成地址对象；请改用 URL 分类",
		"negated source cannot be resolved exactly":                                        "取反的源无法精确解析",
		"something new": "something new",
	} {
		if got := zhReason(in); got != want {
			t.Errorf("zhReason(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestZhReason_CoversLibraryReasons: every fixed reason the library writes
// has a translation (templates with values are covered above).
func TestZhReason_CoversLibraryReasons(t *testing.T) {
	t.Parallel()
	english := regexp.MustCompile(`\b[a-z]{2,} [a-z]{2,} [a-z]{2,}\b`) // three English words: a phrase left as it is
	for _, r := range []string{
		"an operand is empty", "definition not fully modelled: a rollback could not recreate it",
		"named in a configuration line that was not parsed: it may be in use",
		"only exclusions: read as every address except them", "not installed: no route reaches next hop 10.0.0.1",
		"the zone is created; its bridging or tap setup (vswitch, virtual wire) is not translated",
		"an empty service has no form on the target", "ends rounded up to the minute (PAN-OS counts minutes)",
		"application HTTP written as web-browsing (same protocol, vendor signatures differ)",
		"applications teamviewer have no mapping and their ports are unknown; map them (--mapping) or the deny is lost",
		"invalid static route attribute", "unrecognized service attribute", "zones trust -> untrust",
	} {
		if got := zhReason(r); english.MatchString(got) {
			t.Errorf("zhReason(%q) = %q: not translated", r, got)
		}
	}
}

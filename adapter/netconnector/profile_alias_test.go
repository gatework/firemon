package netconnector

import "testing"

func TestConnectorProfileAliasesConvertToDomainVendors(t *testing.T) {
	for _, tc := range []struct{ domain, profile string }{{"paloalto", "palo_alto"}, {"srx", "juniper"}, {"huawei", "huawei"}, {"hillstone", "hillstone"}, {"fortinet", "fortinet"}, {"netscreen", "screenos"}, {"asa", "cisco_asa"}} {
		t.Run(tc.domain, func(t *testing.T) {
			if got := domainVendor(tc.profile); got != tc.domain {
				t.Fatalf("%s -> %s", tc.profile, got)
			}
			profile, err := Profile(tc.domain)
			if err != nil {
				t.Fatal(err)
			}
			if got := domainVendor(profile.Name); got != tc.domain {
				t.Fatalf("profile %s -> %s", profile.Name, got)
			}
		})
	}
	if domainVendor("h3c") != "" {
		t.Fatal("unsupported vendor accepted")
	}
}

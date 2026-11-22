package paloalto

import (
	"strings"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// hillstoneToPAN maps StoneOS application names (lowercase) to the PAN-OS
// applications of the same protocol. The vendors identify applications
// with their own signatures, so a mapped application is an approximation
// the report states; a mapping file overrides any entry.
var hillstoneToPAN = map[string]string{
	"bgp": "bgp", "dcerpc": "msrpc", "dns": "dns", "ftp": "ftp", "git": "git",
	"http": "web-browsing", "http-audio": "web-browsing", "http-download": "web-browsing",
	"http-ext": "web-browsing", "http-fileupload": "web-browsing", "http-range": "web-browsing",
	"http-video": "web-browsing", "http2": "http2", "http-proxy": "http-proxy", "https": "ssl", "icmp": "icmp",
	"kerberos": "kerberos", "ldap": "ldap", "ms-sql": "mssql-db", "ms-sql-mon": "mssql-mon",
	"msrpc": "msrpc", "mysql": "mysql", "ntp": "ntp", "oracle": "oracle", "ospf": "ospf",
	"ping": "ping", "postgresql": "postgres", "rdp": "ms-rdp", "redis": "redis",
	"smb": "ms-ds-smb", "smb2": "ms-ds-smb", "smtp": "smtp", "snmp": "snmp",
	"ssh": "ssh", "ssh-putty": "ssh", "ssl3": "ssl", "syslog": "syslog", "telnet": "telnet",
	"tftp": "tftp", "tls1": "ssl", "websocket": "websocket",
}

func applicationAlias(source firemon.Vendor, name string) (string, bool) {
	if source != firemon.VendorHillstone {
		return "", false
	}
	alias, ok := hillstoneToPAN[strings.ToLower(name)]
	return alias, ok
}

// serviceApplication maps portless services to App-ID signatures.
func serviceApplication(set traffic.ServiceSet) (string, bool) {
	echo, err := traffic.ParseServiceSet("icmp/8")
	if err != nil {
		return "", false
	}
	switch {
	case set.Equal(traffic.ProtocolService(traffic.ProtocolICMP)):
		return "icmp", true
	case set.Equal(echo):
		return "ping", true
	}
	return "", false
}

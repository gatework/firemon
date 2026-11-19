package migrate

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

// panToHillstone maps PAN-OS application names to StoneOS ones.
var panToHillstone = map[string]string{
	"bgp": "BGP", "dns": "DNS", "ftp": "FTP", "git": "GIT", "http-proxy": "HTTP-Proxy",
	"icmp": "ICMP", "kerberos": "Kerberos", "ldap": "LDAP", "ms-ds-smb": "SMB", "ms-rdp": "RDP",
	"msrpc": "MSRPC", "mssql-db": "MS-SQL", "mssql-mon": "MS-SQL-MON", "mysql": "MySQL",
	"ntp": "NTP", "oracle": "ORACLE", "ospf": "OSPF", "ping": "PING", "postgres": "PostgreSQL",
	"redis": "Redis", "smtp": "SMTP", "snmp": "SNMP", "ssh": "SSH", "ssl": "HTTPS",
	"syslog": "SYSLOG", "telnet": "TELNET", "tftp": "TFTP", "web-browsing": "HTTP", "websocket": "WebSocket",
}

// application returns the target name of a source application: from the
// mapping file (exact), from the built-in table (approximate), or none.
func (tr *translator) application(a string) (target string, approx, ok bool) {
	if t, ok := tr.m.Applications[a]; ok {
		return t, false, true
	}
	var table map[string]string
	switch {
	case tr.src.Vendor == firemon.VendorHillstone && tr.t.Vendor == firemon.VendorPaloAlto:
		table = hillstoneToPAN
	case tr.src.Vendor == firemon.VendorPaloAlto && tr.t.Vendor == firemon.VendorHillstone:
		table = panToHillstone
	}
	t, ok := table[strings.ToLower(a)]
	return t, true, ok
}

// portlessApplication returns the target application that matches a
// service without ports, on targets whose services carry only ports: any
// ICMP is icmp, an ICMP echo request is ping.
func (tr *translator) portlessApplication(set traffic.ServiceSet) (string, bool) {
	if tr.caps.MultiProtocolServices || tr.t.Vendor != firemon.VendorPaloAlto {
		return "", false
	}
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

// applicationPorts returns the default ports of every application, when
// all are known.
func (tr *translator) applicationPorts(apps []string) (traffic.ServiceSet, bool) {
	var out traffic.ServiceSet
	for _, a := range apps {
		ports, ok := tr.fw.ApplicationPorts(a)
		if !ok || ports.IsEmpty() {
			return traffic.ServiceSet{}, false
		}
		out = out.Union(ports)
	}
	return out, true
}

// serviceEntries writes a service set as entries, one per protocol.
func serviceEntries(set traffic.ServiceSet) []firemon.ServiceEntry {
	var entries []firemon.ServiceEntry
	for r := range set.All() {
		for p := int(r.ProtocolLow); p <= int(r.ProtocolHigh); p++ {
			entries = append(entries, firemon.ServiceEntry{Protocol: traffic.Protocol(p), Src: r.Src, Dst: r.Dst})
		}
	}
	return entries
}

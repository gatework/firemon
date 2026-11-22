package hillstone

import (
	"strings"

	"github.com/gatework/firemon"
)

// panToHillstone maps PAN-OS application names to StoneOS ones.
var panToHillstone = map[string]string{
	"bgp": "BGP", "dns": "DNS", "ftp": "FTP", "git": "GIT", "http-proxy": "HTTP-Proxy",
	"icmp": "ICMP", "kerberos": "Kerberos", "ldap": "LDAP", "ms-ds-smb": "SMB", "ms-rdp": "RDP",
	"msrpc": "MSRPC", "mssql-db": "MS-SQL", "mssql-mon": "MS-SQL-MON", "mysql": "MySQL",
	"ntp": "NTP", "oracle": "ORACLE", "ospf": "OSPF", "ping": "PING", "postgres": "PostgreSQL",
	"redis": "Redis", "smtp": "SMTP", "snmp": "SNMP", "ssh": "SSH", "ssl": "HTTPS",
	"syslog": "SYSLOG", "telnet": "TELNET", "tftp": "TFTP", "web-browsing": "HTTP", "websocket": "WebSocket",
}

func applicationAlias(source firemon.Vendor, name string) (string, bool) {
	if source != firemon.VendorPaloAlto {
		return "", false
	}
	alias, ok := panToHillstone[strings.ToLower(name)]
	return alias, ok
}

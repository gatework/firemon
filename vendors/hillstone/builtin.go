package hillstone

import (
	"net/netip"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// builtinAddresses returns the StoneOS predefined address objects that the
// configuration references without declaring.
func builtinAddresses(declared *catalog[addressDraft]) []firemon.Address {
	all := []firemon.Address{
		{Name: anyName, Predefined: true, Entries: []firemon.AddressEntry{
			firemon.PrefixEntry(netip.MustParsePrefix("0.0.0.0/0")), firemon.PrefixEntry(netip.MustParsePrefix("::/0")),
		}},
		{Name: "IPv6-any", Predefined: true, Entries: []firemon.AddressEntry{firemon.PrefixEntry(netip.MustParsePrefix("::/0"))}},
	}
	var out []firemon.Address
	for _, a := range all {
		if !declared.has(a.Name) {
			out = append(out, a)
		}
	}
	return out
}

// builtinServices returns the StoneOS 5.5 predefined services that the
// configuration does not declare itself. Services whose definition is not
// documented precisely (for example HTTP-EXT) are left out on purpose, so
// rules using them stay undecidable instead of matching the wrong ports.
func builtinServices(declared *catalog[firemon.Service], groups *catalog[firemon.ServiceGroup]) []firemon.Service {
	tcp := func(lo, hi uint16) firemon.ServiceEntry {
		return firemon.PortEntry(traffic.ProtocolTCP, traffic.PortRange{Low: lo, High: hi})
	}
	udp := func(lo, hi uint16) firemon.ServiceEntry {
		return firemon.PortEntry(traffic.ProtocolUDP, traffic.PortRange{Low: lo, High: hi})
	}
	proto := func(p traffic.Protocol) firemon.ServiceEntry {
		return firemon.ServiceEntry{Protocol: p, Src: traffic.AnyPort, Dst: traffic.AnyPort}
	}
	icmp := func(p traffic.Protocol, typ uint8) firemon.ServiceEntry {
		return firemon.ServiceEntry{Protocol: p, Src: traffic.AnyPort, Dst: traffic.ICMPRange(typ, 0, 0xff)}
	}
	table := map[string][]firemon.ServiceEntry{
		anyName:      {{AnyProtocol: true}},
		"HTTP":       {tcp(80, 80)},
		"HTTPS":      {tcp(443, 443)},
		"SSH":        {tcp(22, 22)},
		"TELNET":     {tcp(23, 23)},
		"FTP":        {tcp(21, 21)},
		"SMTP":       {tcp(25, 25)},
		"POP3":       {tcp(110, 110)},
		"IMAP":       {tcp(143, 143)},
		"NNTP":       {tcp(119, 119)},
		"DNS":        {tcp(53, 53), udp(53, 53)},
		"NTP":        {udp(123, 123)},
		"SNMP":       {udp(161, 162)},
		"SYSLOG":     {udp(514, 514)},
		"RADIUS":     {udp(1812, 1813)},
		"DHCP-Relay": {udp(67, 68)},
		"MDNS":       {udp(5353, 5353)},
		"RDP":        {tcp(3389, 3389)},
		"MySQL":      {tcp(3306, 3306)},
		"BGP":        {tcp(179, 179)},
		"SMB":        {tcp(139, 139), tcp(445, 445)},
		"MSRPC":      {tcp(135, 135)},
		"SUNRPC":     {tcp(111, 111), udp(111, 111)},
		"NFS":        {tcp(2049, 2049), udp(2049, 2049)},
		"OSPF":       {proto(89)},
		"ICMP":       {proto(traffic.ProtocolICMP)},
		"ICMPv6":     {proto(traffic.ProtocolICMPv6)},
		"PING":       {icmp(traffic.ProtocolICMP, 8)},
		"PING6":      {icmp(traffic.ProtocolICMPv6, 128)},
	}
	var out []firemon.Service
	for _, name := range sortedKeys(table) {
		if !declared.has(name) && !groups.has(name) {
			out = append(out, firemon.Service{Name: name, Entries: table[name], Predefined: true})
		}
	}
	return out
}

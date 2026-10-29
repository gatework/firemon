package fortinet

import (
	"context"
	"strconv"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func (p *parser) policies(ctx context.Context, s *config.Session) error {
	tx := s.Cursor().Begin()
	defer tx.Rollback()
	var d fm.Data
	err := p.each(ctx, tx, "firewall policy", func(b *config.Block) {
		id := b.Header.Words[1]
		r := fm.RuleRecord{Object: object(id, id, p.vdom), RuleSet: "security", Position: len(d.Rules), Action: fm.Deny, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant}
		f := readFields(tx, b, &r.Object)
		if n, e := strconv.ParseUint(id, 10, 32); e != nil || n == 0 {
			f.invalid("policy ID")
		}
		r.Name = f.one("name", id)
		r.Description = f.one("comments", "")
		r.Disabled = f.choice("status", "enable", "enable", "disable") == "disable"
		switch f.choice("action", "deny", "deny", "accept", "ipsec") {
		case "accept":
			r.Action = fm.Permit
		case "ipsec":
			f.invalid("IPsec policy action")
		}
		r.Match.FromZones, r.Match.AnyFromZone = p.policyZones(f, "srcintf")
		r.Match.ToZones, r.Match.AnyToZone = p.policyZones(f, "dstintf")
		for _, name := range f.list("srcaddr") {
			r.Match.Sources = append(r.Match.Sources, p.addressRef(name))
		}
		for _, name := range f.list("dstaddr") {
			r.Match.Destinations = append(r.Match.Destinations, p.addressRef(name))
		}
		for _, name := range f.list("service") {
			r.Match.Services = append(r.Match.Services, p.serviceRef(name))
		}
		if len(r.Match.Sources) == 0 || len(r.Match.Destinations) == 0 || len(r.Match.Services) == 0 {
			f.invalid("missing policy selector")
		}
		if name := f.one("schedule", ""); name != "always" {
			r.Match.Schedule = fm.ID(name)
			if name == "" {
				f.invalid("missing schedule")
			}
		}
		switch f.choice("logtraffic", "disable", "disable", "all", "utm") {
		case "all":
			r.Log, r.LogEnd = fm.Known, fm.Known
		case "utm":
			f.invalid("UTM-dependent logging")
		}
		if f.choice("logtraffic-start", "disable", "disable", "enable") == "enable" {
			r.Log, r.LogStart = fm.Known, fm.Known
		}
		f.ignore("uuid")
		mode := f.one("match-vip", "")
		if r.Action == fm.Deny {
			switch mode {
			case "enable":
				r.MatchVIP = fm.Known
			case "disable":
				r.MatchVIP = fm.Irrelevant
			case "":
				r.MatchVIP = defaultMatchVIP(p.data.Metadata.Software)
			default:
				f.invalid("match-vip")
			}
		} else if mode != "" && mode != "disable" {
			f.invalid("match-vip on accepting policy")
		}
		nat := p.policyNAT(f, r)
		f.finish()
		if nat != nil {
			nat.Unsupported = append(nat.Unsupported, r.Unsupported...)
			d.DynamicNATs = append(d.DynamicNATs, *nat)
		}
		d.Rules = append(d.Rules, r)
	})
	if err != nil {
		return err
	}
	// Intrazone allow is a zone setting, not a user policy that can be edited.
	all4 := fm.AddressRef{Kind: fm.AddressObject, ID: "$all-ipv4"}
	for _, id := range p.intraAllow {
		r := fm.RuleRecord{Object: object("$intrazone:"+string(id), "", p.vdom), RuleSet: "security", Position: len(d.Rules), Builtin: true, Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, Match: fm.Match{Sources: []fm.AddressRef{all4}, Destinations: []fm.AddressRef{all4}, AnyService: true, FromZones: []fm.ID{id}, ToZones: []fm.ID{id}}}
		d.Rules = append(d.Rules, r)
	}
	d.Rules = append(d.Rules, fm.RuleRecord{Object: object("$default", "", p.vdom), RuleSet: "security", Position: len(d.Rules), Builtin: true, Action: fm.Deny, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, Match: fm.Match{Sources: []fm.AddressRef{all4}, Destinations: []fm.AddressRef{all4}, AnyService: true, AnyFromZone: true, AnyToZone: true}})
	return p.commit(s, tx, d)
}

func defaultMatchVIP(software string) fm.Status {
	version := strings.TrimPrefix(software, "v")
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return fm.Unknown
	}
	var v [3]int
	for i, s := range parts {
		n, e := strconv.Atoi(s)
		if e != nil || n < 0 {
			return fm.Unknown
		}
		v[i] = n
	}
	if v[0] == 7 && (v[1] > 2 || v[1] == 2 && v[2] >= 4) {
		return fm.Known
	}
	if v[0] == 6 || v[0] == 7 && (v[1] < 2 || v[1] == 2 && v[2] < 4) {
		return fm.Irrelevant
	}
	return fm.Unknown
}

# Executes the separately mounted Perl reference against synthetic stdin only.
use v5.44.0;
use strict;
use warnings;
use JSON::PP;
use Firewall::Config::Content::Static;
use Firewall::Utils::Ip;
my %classes = (hillstone => 'Hillstone', huawei => 'Huawei', fortinet => 'Fortinet', srx => 'Srx', netscreen => 'Netscreen', asa => 'Asa');
my $vendor = shift @ARGV // die 'vendor required';
my $type = $classes{$vendor} // die 'unsupported vendor';
my $class = 'Firewall::Config::Parser::' . $type;
eval "require $class"; die $@ if $@;
# Prove the deliberate Content algorithm independently of vendor parsing.
my $probe = Firewall::Config::Content::Static->new(fwId => 1, fwName => 'content-probe', fwType => $type, config => ["first\n", "second\n"]);
die 'unexpected first line' unless $probe->nextUnParsedLine eq 'first';
$probe->ignore;
$probe->goToHead;
die 'deferred line was swallowed' unless $probe->nextUnParsedLine eq 'first';
die 'unexpected second line' unless $probe->nextUnParsedLine eq 'second';
$probe->goToHead;
die 'rewind restored consumed evidence' if defined $probe->nextUnParsedLine;
my @lines = <STDIN>;
my $content = Firewall::Config::Content::Static->new(fwId => 1, fwName => 'synthetic-oracle', fwType => $type, config => \@lines);
my $parser = $class->new(config => $content, preDefinedService => {});
$parser->parse;
my $elements = $parser->elements;
my $ip = Firewall::Utils::Ip->new;
sub ranges($set) {
 return [map {$ip->changeIntToIp($set->mins->[$_]) . '-' . $ip->changeIntToIp($set->maxs->[$_])} 0 .. $set->length - 1];
}
sub ports($object) {
 my @ports;
 for my $protocol (sort keys %{$object->dstPortRangeMap}) {
  my $set = $object->dstPortRangeMap->{$protocol};
  push @ports, map {$protocol . ':' . $set->mins->[$_] . '-' . $set->maxs->[$_]} 0 .. $set->length - 1;
 }
 return \@ports;
}
my (%addresses, %services, %interfaces);
my @rules;
for my $kind ('address', 'addressGroup') {
 for my $a (values %{$elements->$kind}) {
  my $name = $kind eq 'address' ? $a->addrName : $a->addrGroupName;
  # Both implementations differ in representing literal objects versus groups.
  # The common contract is the named object's resolved address/service view.
  next unless $name eq 'leaf' || $name eq 'hosts';
  $addresses{$name} = ranges($a->range);
 }
}
for my $kind ('service', 'serviceGroup') {
 for my $s (values %{$elements->$kind}) {
  my $name = $kind eq 'service' ? $s->srvName : $s->srvGroupName;
  next unless $name eq 'web' || $name eq 'apps';
  $services{$name} = ports($s);
 }
}
for my $i (values %{$elements->interface}) {
 my $mask = $i->mask;
 $mask = $ip->changeMaskToNumForm($mask) if defined($mask) && $mask =~ /\./;
 $interfaces{$i->name} = ($i->zoneName // '') . ':' . ($i->ipAddress // '') . '/' . ($mask // '');
}
for my $r (sort {($a->ruleNum // 0) <=> ($b->ruleNum // 0)} values %{$elements->rule}) {
 next if $r->ignore;
 push @rules, {action => ($r->action eq 'accept' ? 'permit' : $r->action), sources => ranges($r->srcAddressGroup->range), destinations => ranges($r->dstAddressGroup->range), services => ports($r->serviceGroup)};
}
print JSON::PP->new->canonical->pretty->encode({addresses => \%addresses, services => \%services, interfaces => \%interfaces, zones => [sort map {$_->name} values %{$elements->zone}], rules => \@rules});

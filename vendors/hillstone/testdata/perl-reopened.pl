# Optional reference runner; invoke against the user's read-only Perl source.
# It reads only the synthetic fixture on stdin and never opens a device or DB.
use v5.44.0;
use strict;
use warnings;
use JSON::PP;
use Firewall::Config::Content::Static;
use Firewall::Config::Parser::Hillstone;
use Firewall::Utils::Ip;

# Content's "ignore" means defer to a later parsing pass, not discard.
my $probe = Firewall::Config::Content::Static->new(
    fwId => 1, fwName => 'cursor-probe', fwType => 'Hillstone',
    config => ["first\n", "second\n"],
);
die 'unexpected first line' unless $probe->nextUnParsedLine eq 'first';
$probe->ignore;
$probe->goToHead;
die 'ignore consumed pending evidence' unless $probe->nextUnParsedLine eq 'first';
die 'unexpected second line' unless $probe->nextUnParsedLine eq 'second';
$probe->goToHead;
die 'rewind restored consumed evidence' if defined $probe->nextUnParsedLine;

my @lines = <STDIN>;
my $content = Firewall::Config::Content::Static->new(
    fwId => 1, fwName => 'synthetic', fwType => 'Hillstone', config => \@lines,
);
my $parser = Firewall::Config::Parser::Hillstone->new(
    config => $content, preDefinedService => {},
);
$parser->parse;
my $elements = $parser->elements;
my $ip = Firewall::Utils::Ip->new;
my (%addresses, %services, %interfaces);
for my $a (values %{$elements->address}) {
    $addresses{$a->addrName} = [map {
        $ip->changeIntToIp($a->range->mins->[$_]) . '-' .
        $ip->changeIntToIp($a->range->maxs->[$_])
    } 0 .. $a->range->length - 1];
}
for my $kind ('service', 'serviceGroup') {
    for my $s (values %{$elements->$kind}) {
        my $name = $kind eq 'service' ? $s->srvName : $s->srvGroupName;
        my @ports;
        for my $protocol (sort keys %{$s->dstPortRangeMap}) {
            my $set = $s->dstPortRangeMap->{$protocol};
            push @ports, map {
                $protocol . ':' . $set->mins->[$_] . '-' . $set->maxs->[$_]
            } 0 .. $set->length - 1;
        }
        $services{$name} = \@ports;
    }
}
for my $i (values %{$elements->interface}) {
    $interfaces{$i->name} = $i->zoneName . ':' . $i->ipAddress . '/' .
        $ip->changeMaskToNumForm($i->mask);
}
print JSON::PP->new->canonical->pretty->encode({
    addresses => \%addresses, services => \%services, interfaces => \%interfaces,
    zones => [sort map { $_->name } values %{$elements->zone}],
});

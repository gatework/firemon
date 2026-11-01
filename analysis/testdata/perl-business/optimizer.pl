use v5.44.0;
use strict;
use warnings;
use JSON::PP;
use Firewall::FireFlow::RuleOtimize;
use Firewall::Utils::Ip;
my $raw=do { local $/; <STDIN> };
my $cases=JSON::PP->new->decode($raw);
my $ip=Firewall::Utils::Ip->new;
sub ranges($set) {
 return [map {[$ip->changeIntToIp($set->mins->[$_]),$ip->changeIntToIp($set->maxs->[$_])]} 0 .. $set->length-1];
}
my @result;
for my $case (@$cases) {
 my $out=Firewall::FireFlow::RuleOtimize->new->optimizeRule($case->{rules});
 my @rules;
 for my $r (values %$out) {
  push @rules,{sources=>ranges($r->{srcset}),destinations=>ranges($r->{dstset}),services=>[map {[$r->{serset}->mins->[$_],$r->{serset}->maxs->[$_]]} 0 .. $r->{serset}->length-1]};
 }
 @rules=sort {JSON::PP->new->canonical->encode($a) cmp JSON::PP->new->canonical->encode($b)} @rules;
 push @result,{name=>$case->{name},rules=>\@rules};
}
print JSON::PP->new->canonical->pretty->encode(\@result);

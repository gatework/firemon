use v5.44.0;
use strict;
use warnings;
use JSON::PP;
use Firewall::Policy::Searcher::Report::FwInfo;
my @output;
for my $vendor (qw(Hillstone Srx Fortinet Netscreen Asa)) {
 my $class='Firewall::Policy::Designer::'.$vendor;
 eval "require $class"; die $@ if $@;
 my $info=bless {fromZone=>'inside',toZone=>'outside'},'Firewall::Policy::Searcher::Report::FwInfo';
 my $designer=bless {commandText=>[],searcherReportFwInfo=>$info},$class;
 my $intent={realIp=>'192.0.2.10/32',ruleSet=>'synthetic',natInfo=>{natIp=>'203.0.113.10/32',natType=>'static',interface=>'ethernet0/1'}};
 if ($vendor eq 'Asa') { $designer->newCheckAndCreateNat({natSrc=>$intent}); }
 else { $designer->createStaticNat($intent); }
 push @output,{vendor=>lc($vendor),commands=>$designer->commandText};
}
print JSON::PP->new->canonical->pretty->encode(\@output);

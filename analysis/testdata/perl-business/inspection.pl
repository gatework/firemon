use v5.44.0;
use strict;
use warnings;
use JSON::PP;
use Firewall::Config::Content::Static;
use Firewall::Policy::FindIp;
use Firewall::Utils::Ip;
my %classes=(hillstone=>'Hillstone',fortinet=>'Fortinet',huawei=>'Huawei',srx=>'Srx',netscreen=>'Netscreen',asa=>'Asa');
my $vendor=shift @ARGV // die 'vendor required';
my $type=$classes{$vendor} // die 'unknown vendor';
my $class='Firewall::Config::Parser::'.$type;
eval "require $class"; die $@ if $@;
my @lines=<STDIN>;
my $content=Firewall::Config::Content::Static->new(fwId=>1,fwName=>'synthetic',fwType=>$type,config=>\@lines);
my $parser=$class->new(config=>$content,preDefinedService=>{});
$parser->parse;
my $finder=bless {},'Firewall::Policy::FindIp';
my @cases;
for my $input ('192.0.2.10/32','192.0.2.0/24','192.0.2.11/32') {
 my $groups=$finder->searchAddressGroup($parser,$input,'inside');
 push @cases,{input=>$input,groups=>$groups//{}};
}
print JSON::PP->new->canonical->pretty->encode({vendor=>$vendor,cases=>\@cases});

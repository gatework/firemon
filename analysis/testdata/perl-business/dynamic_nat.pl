use v5.44.0;
use strict;
use warnings;
use JSON::PP;
use Firewall::Config::Content::Static;
use Firewall::Utils::Ip;
use Firewall::Policy::Searcher::Report::FwInfo;
my %classes=(hillstone=>'Hillstone',srx=>'Srx',fortinet=>'Fortinet',netscreen=>'Netscreen',asa=>'Asa');
my $vendor=shift @ARGV // die 'vendor';
my $type=$classes{$vendor} // die 'unsupported';
my $parserClass='Firewall::Config::Parser::'.$type;
my $designerClass='Firewall::Policy::Designer::'.$type;
eval "require $parserClass; require $designerClass"; die $@ if $@;
my @lines=<STDIN>;
my $content=Firewall::Config::Content::Static->new(fwId=>1,fwName=>'synthetic',fwType=>$type,config=>\@lines);
my $parser=$parserClass->new(config=>$content,preDefinedService=>{});$parser->parse;
my @cases=(['source_pool','natSrc','192.0.2.10/32','203.0.113.30/32']);
if ($vendor ne 'asa') {push @cases,['source_interface','natSrc','192.0.2.10/32',undef];}
if ($vendor eq 'srx' || $vendor eq 'hillstone' || $vendor eq 'netscreen') {push @cases,['destination','natDst','192.0.2.10/32','203.0.113.10/32'];}
if ($vendor eq 'netscreen') {$cases[0][3]='192.0.2.100/32';}
my @out;
for my $case (@cases) {
 my ($name,$direction,$real,$public)=@$case;
 my $info=bless {fromZone=>'inside',toZone=>'outside',parser=>$parser,srcMap=>{'192.0.2.10/32'=>{}},dstMap=>{'198.51.100.20/32'=>{}},srvMap=>{'tcp/443'=>{origin=>'tcp/443'}}},'Firewall::Policy::Searcher::Report::FwInfo';
 my $designer=bless {commandText=>[],searcherReportFwInfo=>$info},$designerClass;
 my $natInfo={natType=>'dynamic',interface=>'ethernet0/0'};
 $natInfo->{natIp}=$public if defined $public;
 my $intent={realIp=>$real,natInfo=>$natInfo};
 my $returned;
 if ($vendor eq 'asa') {$returned=$designer->newCheckAndCreateNat({$direction=>$intent});}
 else {$returned=$designer->createDyNat({$direction=>{synthetic=>{$real=>$intent}}});}
 push @out,{case=>$name,direction=>$direction,real=>$real,public=>$public,commands=>$designer->commandText,returned=>$returned};
}
print JSON::PP->new->canonical->pretty->encode({vendor=>$vendor,cases=>\@out});

use v5.44.0;
use strict;
use warnings;
use JSON::PP;
use Firewall::Utils::Date;
use Firewall::Utils::Ip;
use Firewall::Policy::Designer::Huawei;
use Firewall::Policy::Searcher::Report::FwInfo;
my @output;
for my $case (
 ['source_range','natSrc','192.0.2.0/24','203.0.113.10-203.0.113.20',{}],
 ['source_prefix','natSrc','192.0.2.10/32','203.0.113.10/32',{}],
 ['destination_port','natDst','192.0.2.10/32','203.0.113.10/32',{'tcp/443'=>{natPort=>8443}}]
) {
 my ($name,$type,$real,$public,$services)=@$case;
 my $info=bless {fromZone=>'inside',toZone=>'outside',srvMap=>$services},'Firewall::Policy::Searcher::Report::FwInfo';
 my $designer=bless {commandText=>[],searcherReportFwInfo=>$info},'Firewall::Policy::Designer::Huawei';
 $designer->newCheckAndCreateNat({$type=>{realIp=>$real,natInfo=>{natIp=>$public,natType=>'dynamic'}}});
 push @output,{case=>$name,type=>$type,real=>$real,public=>$public,commands=>$designer->commandText};
}
print JSON::PP->new->canonical->pretty->encode(\@output);

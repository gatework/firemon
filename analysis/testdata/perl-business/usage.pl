use v5.44.0;
use strict;
use warnings;
use JSON::PP;
use Firewall::Config::Content::Static;
use Firewall::Policy::Cleaner::AnalyzeLog;
my %classes=(asa=>'Asa',srx=>'Srx',netscreen=>'Netscreen');
my $vendor=shift @ARGV // die 'vendor';my $type=$classes{$vendor} // die 'unsupported';
my $class='Firewall::Config::Parser::'.$type;eval "require $class";die $@ if $@;
my @lines=<STDIN>;
my $content=Firewall::Config::Content::Static->new(fwId=>1,fwName=>'synthetic',fwType=>$type,config=>\@lines);
my $parser=$class->new(config=>$content,preDefinedService=>{});$parser->parse;
# Legacy error sink is confined to the ephemeral /wls tmpfs.
mkdir '/wls/firewall_log' or die $! unless -d '/wls/firewall_log';
my $analyzer=Firewall::Policy::Cleaner::AnalyzeLog->new(protocol=>{6=>'tcp',17=>'udp',1=>'icmp'});
my $flags=$analyzer->$vendor(file=>'/oracle/'.$vendor.'-usage.log',parser=>$parser,fwName=>'synthetic');
my %out;
for my $sign (sort keys %$flags) {
 my $r=$flags->{$sign};
 $out{$sign}={hit=>($r->{flag}//0),sources=>[sort keys %{$r->{match}{matchSrc}//{}}],destinations=>[sort keys %{$r->{match}{matchDst}//{}}],services=>[sort keys %{$r->{match}{matchSrv}//{}}]};
}
print JSON::PP->new->canonical->pretty->encode({vendor=>$vendor,rules=>\%out});

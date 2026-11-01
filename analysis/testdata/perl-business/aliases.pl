use v5.44.0;
use strict;
use warnings;
use JSON::PP;
use Firewall::Config::Content::Static;
use Firewall::Config::Parser::Srx;
use Firewall::Policy::Searcher::Srx;
my @lines=<STDIN>;
my $content=Firewall::Config::Content::Static->new(fwId=>1,fwName=>'synthetic',fwType=>'Srx',config=>\@lines);
my $parser=Firewall::Config::Parser::Srx->new(config=>$content,preDefinedService=>{});$parser->parse;
my $searcher=Firewall::Policy::Searcher::Srx->new;
my @results;
for my $real ('192.0.2.10/32','192.0.2.128/25') {
 my $main=$searcher->createMainAddr($real,'outside',$parser);
 die 'main alias missing' unless defined $main->{natIp};
 my ($private,$zone)=$searcher->createPrivateIp($main->{natIp},$parser);
 push @results,{real=>$real,public=>$main->{natIp},roundtrip=>$private,zone=>$zone};
}
print JSON::PP->new->canonical->pretty->encode(\@results);

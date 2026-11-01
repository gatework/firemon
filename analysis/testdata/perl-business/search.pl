use v5.44.0;
use strict;
use warnings;
use JSON::PP;
use Firewall::Config::Content::Static;
use Firewall::Policy::Searcher;
use Firewall::Utils::Cache;
{
    package Local::Searcher;
    our @ISA = ('Firewall::Policy::Searcher');
    sub getParser { $_[0]->{parser} }
    sub getAnalyzerReport { $_[0]->{parser}->report }
    # Perl 5.44 disables indirect constructor syntax in legacy getObj's eval.
    # Keep plugin algorithms intact; adapt the factory boundary only.
    sub getObj {
        my ($self,$type)=@_;
        my $class='Firewall::Policy::Searcher::'.$type;
        eval "require $class"; die $@ if $@;
        return $class->new;
    }
}
my %classes = (hillstone=>'Hillstone',fortinet=>'Fortinet',huawei=>'Huawei',srx=>'Srx',netscreen=>'Netscreen',asa=>'Asa');
my $vendor=shift @ARGV // die 'vendor required';
my $type=$classes{$vendor} // die 'unknown vendor';
my $class='Firewall::Config::Parser::'.$type;
eval "require $class"; die $@ if $@;
my @lines=<STDIN>;
my $content=Firewall::Config::Content::Static->new(fwId=>1,fwName=>'synthetic',fwType=>$type,config=>\@lines);
my $parsed=$class->new(config=>$content,preDefinedService=>{});
$parsed->parse;
my @cases=(['covered','192.0.2.10/32','192.0.2.10/32','tcp/80','tcp/443'],['append-source','192.0.2.11/32','192.0.2.10/32','tcp/80','tcp/443'],['create-two-axes','192.0.2.11/32','192.0.2.12/32','tcp/80','tcp/443'],['append-service','192.0.2.10/32','192.0.2.10/32','tcp/8080']);
my @results;
for my $case (@cases) {
    my ($name,$src,$dst,@srv)=@$case;
    my $searcher=bless {parser=>$parsed,cache=>Firewall::Utils::Cache->new},'Local::Searcher';
    my $valid=$searcher->getValidRuleSign(1,$type,'inside','inside',0,'src');
    my $result=$searcher->searchPolicy({srcMap=>{$src=>{origin=>$src}},dstMap=>{$dst=>{origin=>$dst}},srvMap=>{map {$_=>{origin=>$_}} @srv},fwId=>1,fwType=>$type,fromZone=>'inside',toZone=>'inside',validRuleSign=>$valid,isNat=>0,hit=>'src',schedule=>{enddate=>'always'}});
    push @results,{name=>$name,type=>$result->{type},rule=>defined($result->{ruleObj})?$result->{ruleObj}->sign:undef};
}
print JSON::PP->new->canonical->pretty->encode({vendor=>$vendor,cases=>\@results});

use v5.44.0;
use strict;
use warnings;
use JSON::PP;
use Firewall::Config::Content::Static;
use Firewall::Config::Ruleopti;
{
 package Local::DAO;
 sub loadParser { $_[0]->{parser} }
 package Local::DB;
 sub delete { return }
 sub batchExecute { $_[0]->{rows}=$_[1] }
 sub execute { return }
}
my %classes=(hillstone=>'Hillstone',fortinet=>'Fortinet',huawei=>'Huawei',srx=>'Srx',netscreen=>'Netscreen',asa=>'Asa');
my $vendor=shift @ARGV // die 'vendor';my $type=$classes{$vendor} // die 'unsupported';
my $class='Firewall::Config::Parser::'.$type;eval "require $class";die $@ if $@;
my @lines=<STDIN>;
my $content=Firewall::Config::Content::Static->new(fwId=>1,fwName=>'synthetic',fwType=>$type,config=>\@lines);
my $parser=$class->new(config=>$content,preDefinedService=>{});$parser->parse;
my $db=bless {rows=>[]},'Local::DB';
my $opt=bless {dbi=>$db},'Firewall::Config::Ruleopti';
{
 no warnings 'redefine';
 # Only DAO load and result persistence boundaries are replaced.
 local *Firewall::Config::Dao::Parser::new=sub { return bless {parser=>$parser},'Local::DAO' };
 $opt->optirule(1);
}
my @out;
for my $row (@{$db->{rows}//[]}) {
 for my $other (@{JSON::PP->new->decode($row->[3])}) {
  # Equal declarations may be visited in either hash order; retain unordered pair.
  push @out,{kind=>$row->[2],rules=>[sort($row->[1],$other)]};
 }
}
@out=sort {JSON::PP->new->canonical->encode($a) cmp JSON::PP->new->canonical->encode($b)} @out;
print JSON::PP->new->canonical->pretty->encode({vendor=>$vendor,candidates=>\@out});

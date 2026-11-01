use v5.44.0;
use strict;
use warnings;
use JSON::PP;
use Firewall::Config::Audit;
use Firewall::Utils::Set;
my $audit=Firewall::Config::Audit->new;
my $policy={srcset=>Firewall::Utils::Set->new(1,2),dstset=>Firewall::Utils::Set->new(10,10),srvset=>Firewall::Utils::Set->new(443,443)};
my @cases=(
 ['and-equal','and',[{type=>'src',relation=>'eq',range=>Firewall::Utils::Set->new(1,2)},{type=>'port',relation=>'eq',range=>Firewall::Utils::Set->new(443,443)}]],
 ['and-disjoint-cross','and',[{type=>'src',relation=>'cross',range=>Firewall::Utils::Set->new(3,4)}]],
 ['or-disjoint-cross','or',[{type=>'src',relation=>'cross',range=>Firewall::Utils::Set->new(3,4)}]],
 ['or-contained','or',[{type=>'src',relation=>'contain',range=>Firewall::Utils::Set->new(1,1)}]],
 ['equal-not-equal','and',[{type=>'src',relation=>'neq',range=>Firewall::Utils::Set->new(1,2)}]]
);
my @out;
for my $case (@cases) {
 my ($name,$relation,$content)=@$case;
 my $hits=$audit->_audit($policy,[{id=>$name,contentSet=>{relation=>$relation,content=>$content}}]);
 push @out,{name=>$name,hit=>scalar(@$hits)?JSON::PP::true:JSON::PP::false};
}
print JSON::PP->new->canonical->pretty->encode(\@out);

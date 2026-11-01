use v5.44.0;
use strict;
use warnings;
use JSON::PP;
my @output;
for my $vendor (qw(Hillstone Fortinet Huawei Netscreen)) {
 my $class='Firewall::Policy::Designer::'.$vendor;
 eval "require $class"; die $@ if $@;
 for my $hour (10,11) {
  # Only command accumulation is required by this actual method; no DB/network dependency is called.
  my $designer=bless {commandText=>[]},$class;
  my $name=$designer->createSchedule({startdate=>'2026-11-01 09:00',enddate=>"2026-11-01 $hour:00"});
  push @output,{vendor=>lc($vendor),end_hour=>$hour,name=>$name,commands=>$designer->commandText};
 }
}
print JSON::PP->new->canonical->pretty->encode(\@output);

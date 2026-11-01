use v5.44.0;
use strict;
use warnings;
use JSON::PP;
use Time::Local qw(timegm);
my @output;
my $start=timegm(0,0,9,1,10,2026);
my $end=timegm(0,0,10,1,10,2026);
for my $vendor (qw(Hillstone Fortinet Huawei Netscreen)) {
 my $class='Firewall::Config::Element::Schedule::'.$vendor;
 eval "require $class"; die $@ if $@;
 my ($from,$to)= $vendor eq 'Huawei'
  ? ('09:00:00 2026/11/01','10:00:00 2026/11/01')
  : $vendor eq 'Fortinet'
  ? ('09:00 2026/11/01','10:00 2026/11/01')
  : ('11/01/2026 09:00','11/01/2026 10:00');
 my $schedule=$class->new(schName=>'synthetic_window',schType=>$vendor eq 'Netscreen'?'once':'onetime',startDate=>$from,endDate=>$to);
 my @checks;
 for my $at ($start-1,$start,$end-1,$end,$end+1) {
  push @checks,{at_epoch=>$at,active=>0+$schedule->isEnable($at)};
 }
 push @output,{vendor=>lc($vendor),process_timezone=>$ENV{TZ},checks=>\@checks};
}
print JSON::PP->new->canonical->pretty->encode(\@output);

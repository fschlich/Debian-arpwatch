#! /usr/bin/perl

# print arpwatch records with zero-padded MAC addresses and human
# readable dates

# Craig Sanders <cas@taz.net.au> 2007
#
# this script is too trivial to be anything but public domain. do what
# you want with it.

use Date::Format;

if (!$ARGV[0]) {
 push @ARGV, '/var/lib/arpwatch/eth0.dat';
 push @ARGV, '/var/lib/arpwatch/eth1.dat';
# push @ARGV, '/var/lib/arpwatch/eth2.dat';
}

while(<>) {
  chomp ;
  my ($mac,$ip,$t,$hostname) = split /\t/;

  my @mac = split /:/, $mac;
  $mac = sprintf '%2s:%2s:%2s:%2s:%2s:%2s', @mac;
  $mac =~ s/ /0/g;
  $mac = lc($mac);

  $t = time2str('%Y-%m-%d %H:%M:%S',$t);

  #printf "%s\t%s\t%s\t%s\n",  $mac, $ip, $t, $hostname;
  printf "%17s  %-15s %s\t%s\n",  $mac, $ip, $t, $hostname;
} ;

#!/usr/bin/perl -n
next if /^($|#)/;
@_ = split(/\s+/);
print "cvs rdiff -u -r $_[1] -r $_[2] arpwatch > ../patches/" .lc("$_[0]_$_[2]")."\n";
#print "cvs co -ko -r $_[2] -d " . lc("$_[0]_$_[2]") . " arpwatch \n";

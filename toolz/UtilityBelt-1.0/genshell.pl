#!/usr/bin/perl -w
use strict;
use FindBin qw{$RealBin};
use lib "$RealBin";
do "hacklib.pl";

#print genshell();
print( genshell(@ARGV));

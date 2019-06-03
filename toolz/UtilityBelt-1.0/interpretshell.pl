#!/usr/bin/perl -w
#
#This application will take shellcode (or any binary executable code) from STDIN
#wrap it in a C application wrapper, and compile, then open it in GDB


sub hexify {
    # parameter passed to the subfunction
    my $decnum = shift;
    # the final hex number
    my $hexnum = "";
    my $tempval;
    while ($decnum != 0) {
    # get the remainder (modulus function) by dividing by 16
    $tempval = $decnum % 16;
    # convert to the appropriate letter if the value is greater than 9
    if ($tempval > 9) {
    $tempval = chr($tempval + 55);
    }
    # 'concatenate' the number to what we have so far in what will be the final variable
    $hexnum = $tempval . $hexnum ;
    # new actually divide by 16, and keep the integer value of the answer
    $decnum = int($decnum / 16); 
    # if we cant divide by 16, this is the last step
    if ($decnum < 16) {
    # convert to letters again..
    if ($decnum > 9) {
    $decnum = chr($decnum + 55);
    }
    
    # add this onto the final answer..  reset decnum variable to zero so loop will exit
    $hexnum = $decnum . $hexnum; 
    $decnum = 0 
    }
    }
    return $hexnum;
}

sub interpret {
 my $shellcode = shift || "";
 my $cannonized = "";
 for (my $i = 0; $i<length($shellcode); $i++){
  $cannonized .= "\\x" . hexify(ord(substr($shellcode,$i,1))); 
 }
 return $cannonized;
}




my $dummyC1 = "#include <stdio.h>\n char\n shellcode[] = \"";
my $dummyC2 = "\";\n\n int\n main()\n {\n void (*code)() = (void *)shellcode;\n printf(\"Shellcode length: %d\\n\", strlen(shellcode));\n code();\n return(0);\n }\n";

my $SHELL = <STDIN>;

unlink("/tmp/tmpfile.c");
open(OUT, ">/tmp/tmpfile.c");
print(OUT $dummyC1);
print(OUT interpret($SHELL));
print(OUT $dummyC2);
close(OUT);


`gcc -o /tmp/tmpbinary /tmp/tmpfile.c`;

system("gdb /tmp/tmpbinary");
system("objdump -S /tmp/tmpbinary");

#!/usr/bin/perl -w
#
# disass.pl v1.1 by atlas
#
# Syntax:  ./disass.pl <binary-executable>
#
# disass.pl will use a few simply objdump calls to gather GOT, PLT, and Disassembly information.
# GOT addresses are tied to PLT calls and the PLT lines are tagged with function names
# Then, fulll disassembly is scanned for references to PLT calls, and those lines are labeled
# with the appropriate function call name.  Tested only with *nix.
#
# Yes, this may seem elementary, but I found it helpful so here it is.
# @145



use strict;
my $binary = shift;


my @disassembly = `objdump -S $binary`;
my @GOT = `objdump -R $binary`;
my @HEADERS = `objdump -h $binary`;
my @SYMBOLS = `objdump -t $binary`;
my @BREAK;

### Peal off the first few lines of GOT output
shift(@GOT);
shift(@GOT);
shift(@GOT);
shift(@GOT);

###  Parse GOT section from GOT
for my $LINE (@GOT) {
 my $TEMP = $LINE;
 if ($TEMP =~ /^$/){
  next;
 }
 while ((substr($TEMP,0,1) eq " ") || (substr($TEMP,0,1) eq "0")){
  $TEMP = substr($TEMP,1);
 }

### Tag PLT with GOT names
 my @LIN = split(/\W+/, $TEMP);
 for my $ASMLINE (@disassembly){
  if ($ASMLINE =~ /$LIN[0]/){
   chomp($ASMLINE);
   $ASMLINE .= "\t" . $LIN[2] . "\n";
#print($ASMLINE);

### For each PLT line found, @disassembly is scanned and tagged appropriately
   if ($ASMLINE =~ /jmp.*\*0x.*$LIN[0]/){
    my @PLT = split(/\W+/ , $ASMLINE);
#print("PLT ADDRESS:" . $PLT[1]);
    for my $EACH (@disassembly){
     if ($EACH =~ /^.*:.*$PLT[1]/){
#print("MATCH-TEXT");
      my @breakdown = split(":", $EACH);
      my $address=$breakdown[0];
      $address =~ s/^\W*//;
      push(@BREAK, $address);
      chomp($EACH);
      $EACH .= "\t $LIN[2] (brkpt: ".@BREAK.")\n\n";
     }
    }
   }
  }
 }
}

print("DISASSEMBLY: @disassembly");
print("\n\nGOT: \n@GOT");
print("\n\nHEADERS: \n@HEADERS");
print("\n\nSYMBOLS: \n@SYMBOLS");
print("\n\nBreakpoints for each \"call\":\n");
for my $break (@BREAK){
 print(" break *0x$break\n");
}

print("\n".'DISPLAY SETTINGS/Basic
 display/i $pc
 display/x $edx
 display/x $ecx
 display/x $ebx
 display/x $eax
 display/32wx $ebp-92
 display/32xw $esp
');

#!/usr/bin/python 
#
# disass.py v1.1 by atlas
#
# Syntax:  ./disass.py <binary-executable>
#
# disass.py will use a few simply objdump calls to gather GOT, PLT, and Disassembly information.
# GOT addresses are tied to PLT calls and the PLT lines are tagged with function names
# Then, full disassembly is scanned for references to PLT calls, and those lines are labeled
# with the appropriate function call name.  Tested only with *nix.
#
# Yes, this may seem elementary, but I found it helpful so here it is.
# @145
#     Converted to Python from Perl in 2/2006

import os
import sys
import re

VER=1.1 

if (len(sys.argv) < 2):
  print >>sys.stderr, """
disass v%0.2f Disassembling enhancer

Syntax:  %s <binary-to-disass>

"""  % (VER, sys.argv[0])
  sys.exit(1)


binary = sys.argv[1]

disassembly = os.popen('objdump -S '+binary).readlines()
GOT = os.popen('objdump -R '+binary).readlines()
HEADERS = os.popen('objdump -x '+binary).readlines()
SYMBOLS = os.popen('objdump -t '+binary).readlines()
LIBS = os.popen('objdump -T '+binary).readlines()
BREAK = []

### Peal off the first few lines of GOT output
if (len(GOT) > 5):
  GOT.pop(0)
  GOT.pop(0)
  GOT.pop(0)
  GOT.pop(0)
  GOT.pop(0)




########################## Stage 1: Associate GOT and PLT entries and Tag disassassembly calls to PLT with the appropriate name #############################
###  Parse GOT section from GOT
for LINE in GOT:
  LINE = LINE.strip()
  if (len(LINE) < 1):
    continue
  #
  while (LINE[0] == " " or LINE[0] == "0"):
    LINE = LINE[1:]

### Tag PLT with GOT names
  LIN = re.split("\s+",LINE)
  for each in range(len(disassembly)):
    disassembly[each] = disassembly[each].strip()
    if (re.search(LIN[0], disassembly[each]) >-1):
      disassembly[each] += "\t" + LIN[2] 

### For each PLT line found, disassembly is scanned and tagged appropriately
      if (re.search("jmp.*0x" + LIN[0], disassembly[each]) > -1):
        PLT = re.split("\s+", disassembly[each])
        PLT[0] = PLT[0][:-1]		#trim off the ":" at the end

    ### Now traverse the rest of the disassembly looking for the calls to the PLT for this entry
        for EACH in range(len(disassembly)):
          if (re.search("^.*:.*" + PLT[0],disassembly[EACH]) > -1):
            breakdown = disassembly[EACH].split(":")
            address = breakdown[0]
            re.sub("^\s*", "", address)
            BREAK.append(address)
            disassembly[EACH].strip("\n")
            disassembly[EACH] += "\t %s (brkpt: %i)\n\n" % (LIN[2],len(BREAK)-1)
          #
        #
      #
    #
  #
#

######################### Stage 2: Find all non-PLT calls and tag them with name of subroutine they are calling ###############################

######################### Stage 3: Find all jmp, je, jz, jl, jg, jge, jle, jnz, jns calls #############################
### Check whether inside current sub
##### If same sub and a jump backward, mark that section as a loop
##### ASCII art the jmps?  
      # For each jmp block, check disassembly[line][somechar] for [/\|].  
      ## If found, check [somechar+1] until an empty char is found
      # Insert a "|" for each line in between and a /- or \- as appropriate  (HTML and colors?)



print("DISASSEMBLY:")
for i in  disassembly:
  print(i.strip())
print("\n\nGOT:")
for i in GOT:
  print(i.strip()) 
print("\n\nHEADERS:")
for i in HEADERS:
  print(i.strip())
print("\n\nSYMBOLS:")
for i in SYMBOLS:
  print(i.strip())
print("\n\nBreakpoints for each \"call\":\n");
for brk in BREAK:
  print(" break *0x" + brk)
#

print("""\nDISPLAY SETTINGS/Basic
 display/i $pc
 display/x $edx
 display/x $ecx
 display/x $ebx
 display/x $eax
 display/32wx $ebp-92
 display/32xw $esp 
""")



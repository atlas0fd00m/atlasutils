#!/usr/bin/env python
"""  this script simply grabs EIP and ESP from a core dump, prints each and compares them.  This can be helpful
as a metric while brute-forcing a randomized stack from the commandline. 

dumping core is required ("ulimit -c unlimited" in a bash shell)

This is not an exacting tool.  It simply allows you to tell when you've placed EIP within len(SHELLCODE) after ESP.  It's purpose is 
somewhat of a safeguard, in case your shellcode doesn't work.  
"""
import struct
from sys import stdin,argv
from os import getenv

#shell=getenv("SHELLCODE", "")
MIN=int(argv[1])
MAX=int(argv[2])
f=open('core')
code = f.read()
a=struct.unpack("I",code[0x2c0:0x2c4])[0]
b=struct.unpack("I",code[0x2cc:0x2d0])[0]
d = a-b
#print( "(i)%x - (s)%x = %x (shell=%x)"%(a,b,d, len(shell)))
print( "(i)%x - (s)%x = %x "%(a,b,d))
#if (d>1 and d < len(shell)):
if (d>MIN and d < MAX):
	stdin.readline()
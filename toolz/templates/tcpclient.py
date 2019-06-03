#!/usr/bin/python
import os
import sys
import time
import socket
import select
import string
import struct
#from hacklib import *


port = 115

if (len(sys.argv) < 2):
    host = 'PRIMARY_TARGET_HOSTNAME'
    TEST = 0
else:
    host = sys.argv[1]
    TEST = 1
    if len(sys.argv) > 2:
        port = int(sys.argv[2])

def go(s):
    print >>sys.stderr,("\n[+] Entering Interactive Shell...")
    while True:
        x,y,z = select.select([sys.stdin, s],[],[],.1)
        if s in x:
            ch = s.recv(1000)
            if len(ch) == 0: break
            if all(c in string.printable for c in ch):
                print(ch)
            else:
                print "BIN:%s" % repr(ch)

        if sys.stdin in x:
            ch = os.read(sys.stdin.fileno(), 1000)
            #print(repr(ch))
            s.sendall(ch)

def keystop(delay=0):
        return len(select.select([sys.stdin],[],[],delay)[0])


TIMEOUT = 10

####### Used for fuzzing
#for (my $i = 1038; ; $i++){
#######
# i = 1063 - length($string);

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.getprotobyname('tcp'))
s.connect((host,port))



### all sends can follow this pattern
#s.sendall("FUZZER in need of assistance!\n");    # sendall is send and flush wrapped into one



### all recvs can follow this pattern
#x,y,z = select([s],[],[], TIMEOUT)
#if x:
#	s.recv(65768)
#else:
#	print >>stderr, ('ERROR: Timed out waiting for response from server.')


go(s)

s.close()


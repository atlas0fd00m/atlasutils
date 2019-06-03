#!/usr/bin/python

from socket import *
from sys import *
from hacklib import *
from select import *

if (len(argv) < 2):
	syntax()
	exit(1)

host = argv[1]
port = 6969

####### Used for fuzzing
#for (my $i = 1038; ; $i++){
#######
# i = 1063 - length($string);

s = socket.socket(AF_INET, SOCK_DGRAM, getprotobyname('udp'))
#s.connect((host,port))
s.bind(('0.0.0.0',0))

#s.sendall("FUZZER in need of assistance!\n");
s.sendto("pwd\n\n",(host,port));

cycle = True
while (cycle):
	s.sendto("pwd\r\n",(host,port));
	(x, y, z) = select([s],[],[s],.1)
	if (s in x):
		(input,addy) = s.recvfrom(2000)
		print("(%s) %s"%(addy,input))
		if (len(input) ==0): cycle = False
	#print >>stderr,(".")

s.close()

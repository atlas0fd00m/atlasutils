#!/usr/bin/env python

from socket import *

sock = socket(AF_INET, SOCK_RAW, getprotobyname("chaos"))
while True:
 data,sender = sock.recvfrom(2000)
 print "got %d bytes from %s" % (len(data), repr(sender))
 print "DATA: %s" % (repr(data))

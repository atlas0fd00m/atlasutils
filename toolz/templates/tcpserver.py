#!/usr/bin/env python

from socket import *

s = socket(AF_INET, SOCK_STREAM, getprotobyname("tcp"))
s.bind(("0.0.0.0", 31337))
s.listen(1)
s.setsockopt(SOL_SOCKET,SO_REUSEADDR,1)
sock, addr = s.accept()
sock.setsockopt(SOL_SOCKET,SO_REUSEADDR,1)

while True:
 data = sock.recv(2000)
 if len(data) < 1:
  break
 print "got %d bytes from %s" % (len(data), repr(addr))
 print "DATA: %s" % (repr(data))
 sock.sendall("DATA: %s\n" % (repr(data)))

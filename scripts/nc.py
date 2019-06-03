#!/usr/bin/python
"""
as the name suggests, this is NetCat writtin entirely in Python.  
Not all features are supported from netcat, and additional functionality (RAW sockets) has been added.
see "nc.py --help" for syntax
"""
import sys
from select import *
from socket import *
from os import *


INTERACTIVE = False
MONOGOMOUS = False
LISTENHARDER = False
VERBOSE = False
VERYVERBOSE = False
RAW_SNIFF=False
VER=1.2

class wratchet:
	""" wratchet is a "universal" tool which handles sockets and file-descriptors"""
	# pointers to the actual send and recv methods
	send = None
	recv = None

	s = None

	laddr = None
	lport = None
	rport = None
	raddr = None

	fd = None		# use this for the input
	fd2 = None		# use this for the output descriptor

	def __init__(self, socket = None, laddr = None, lport=None, raddr = None, rport=None, proto=None, isStdin = False):
		
		if socket: self.setSocket(socket)
		if laddr: self.setLAddr(laddr)
		if lport: self.setLPort(lport)
		if raddr: self.setRAddr(raddr)
		if rport: self.setRPort(rport)
		if proto: 
			
			self.setProto(proto)
			if (self.proto != 6):	self.makeRAW()
		else:
			self.makeTCP()
		self.isStdin = isStdin

	def setSocket(self, socket):
		self.s = socket
		self.fd2 = socket.fileno()
		self.fd = socket.fileno()

	def setRAddr(self, addr):
		self.raddr = (addr)

	def setRPort(self, port):
		self.rport = int(port)

	def setLAddr(self, addr):
		self.laddr = (addr)

	def setLPort(self, port):
		self.lport = int(port)

	def setProto(self, proto):
		if (type(proto) == "str"):
			try:
				proto = int(proto)
			except:
				proto = getprotobyname(proto)
		self.proto = proto

	def setFILE(self, fin, fout):
		self.fin = fin
		self.fout = fout
		self.fd = fin.fileno()
		self.fd2 = fout.fileno()

	def setCMD(self,cmd):
		self.fout, self.fin = popen4(cmd, -1)
		self.fd2 = self.fout.fileno()
		self.fd = self.fin.fileno()

	def close(self):
		try:
			close(self.fd)
			close(self.fd2)
		except:
			pass


	def makeTCP(self, s=None):
		if (s):		self.setSocket(s)
		self.send = self.sendTCP
		self.recv = self.recvTCP

	def makeUDP(self, s=None):
		if (s):		self.setSocket(s)
		self.send = self.sendUDP
		self.recv = self.recvUDP
		
	def makeRAW(self, s=None, proto=None):
		if (s):		self.setSocket(s)
		self.send = self.sendRAW
		self.recv = self.recvRAW
		if (proto):	self.setProto(proto)
			
		
	def makeFILE(self, fin=None, fout=None):
		if (fin):	self.setFILE(fin,fout)
		self.send = self.sendFILE
		self.recv = self.recvFILE

	def makeCMD(self, cmd=None):
		if cmd:  self.setCMD(cmd)
		self.send = self.sendCMD
		self.recv = self.recvCMD



	def sendTCP(self, data):
		buf = data
		self.s.setblocking(1)
		self.s.sendall(buf)
		self.s.setblocking(0)
		
	def sendUDP(self, data, addr=None, port=None):
		if (not addr): 
			addr = self.raddr
		if (not port): 
			port = self.rport
		buf = data
		while (len(buf) > 16384):
			self.s.sendto(buf[:16384], (addr,port))
			buf = buf[16384:]
		self.s.sendto(buf, (addr,port))
		
	def sendRAW(self, data, addr=None, port=0):
		if (not addr): 
			addr = self.raddr
		if (self.rport): 
			port = self.rport
		buf = data
		print ("%s %d"%(addr,port))
		while (len(buf) > 16384):
			self.s.sendto(buf[:16384], (addr,port))
			buf = buf[16384:]
		self.s.sendto(data, (addr,port))
		
	def sendFILE(self, data):
		self.fout.write(data)
		self.fout.flush()
		
	def sendCMD(self, data):
		self.sendFILE(data)


	def recvTCP(self,size=1000000):
		data = self.s.recv(size)
		return data

	def recvUDP(self,size=1000000):
		(data, addr) = self.s.recvfrom(size, self.lport)
		if ((not MONOGOMOUS) or (not self.raddr)):  
			self.raddr,d = addr
		if ((not MONOGOMOUS) or (not self.rport)):  
			d,self.rport = addr
		return data
		
	def recvRAW(self,size=1000000):
		(data, addr) = self.s.recvfrom(size, self.laddr)
		if ((not MONOGOMOUS) or (not self.raddr)):  
			self.raddr,d = addr
		if ((not MONOGOMOUS) or (not self.rport)):  
			d,self.rport = addr
		return data
		
	def recvFILE(self,size=1000000):
		data = read(self.fd, size)
		if INTERACTIVE and self.isStdin:
			#print >>sys.stderr,('INTERACTIVE')
			return(eval('"%s"'%data.strip())+'\n')
		return data
		
	def recvCMD(self,size=1000000):
		data = self.recvFILE(size)
		return data

	def select(self, wait=0):
		x, y, z = select([self.fd,self.fd2],[],[self.fd],wait)
		if (self.fd in x): return True
		if (self.fd in z): raise exception
		return False
		
		


def manageConn(wrcht1, wrcht2, wait = None):
	""" manageCommand() handles I/O with a child process
		wrcht1 and wrcht2 are wratchet objects which implement both sides of this communication.

		formerly:
		cmd == command to be executed
		fin == "stdin" equivalent for cmd.  This will be read from
		fout == "stdout" equivalent for cmd.  This will be written to
	"""
	try:
		tmp = None
		idle = 0
		while (True):
			### socket input handling ###
			if (wrcht1.select()):
				idle = 0
				tmp = wrcht1.recv()
				if (len(tmp) == 0):
					break
				if (VERYVERBOSE): sys.stderr.write("sckt: len: %d\n%s"%(len(tmp),tmp))
				wrcht2.send(tmp)
	

			### command input handling ###
			if (wrcht2.select()):
				idle = 0
				tmp = wrcht2.recv()
				if (VERYVERBOSE): sys.stderr.write("cmd:  len: %d\n%s"%(len(tmp),tmp))
				if (len(tmp) == 0): 
					break
				wrcht1.send(tmp)


			idle += 1
			if (wait and idle > (wait*10)):
				break
			select([],[],[], .1)
	except: 
		print >>sys.stderr,("Score!!")
		try:
			sys.excepthook(sys.exc_info()[0],sys.exc_info()[1],sys.exc_info()[2])
			wrcht1.close()
			wrcht2.close()
		except:
			pass
			sys.excepthook(sys.exc_info()[0],sys.exc_info()[1],sys.exc_info()[2])

##################################################

def syntax():
	print """
netcat on python... a crushing experience.  (ver %s)

Syntax:   %s  [-v] [-I] [-l] [-L] [-u] [-p port] [-P proto] [-e cmd] [host [port]]
	-v		verbose
	-I		Interactive - interprets \\x## characters
	-l		listen
	-L		Listen Harder!  (restart connection/listen)
	-u		use UDP  (don't use with -P option; default: TCP)
	-w #		wait # seconds of inactivity before exiting
	-e cmd		connect this socket to a command
	-p port		set local port
	-P proto	use protocol 'proto' (RAW Sockets, must have rights)

"""%(VER, sys.argv[0])
	sys.exit(1)

### TCP server -e
def elistenerTCP(port,cmd):
	try:
		a = None
		s = socket()
		s.setsockopt(SOL_SOCKET,SO_REUSEADDR,1)
		s.bind(("0.0.0.0",int(sys.argv[1])))
		s.listen(10000)
		a,addy = s.accept()
		a.setsockopt(SOL_SOCKET,SO_REUSEADDR,1)
		a.setblocking(False)
		#### as = active socket, addy = address on the other end
		#### let the fun begin
		
		manageCommand(sys.argv[2], a, a)
	
		a.close()
	except:
		print("Error:  %s"%sys.exc_info()[0])
		sys.excepthook(sys.exc_info()[0],sys.exc_info()[1],sys.exc_info()[2])
	a.close()

### UDP server -e
def elisternerUDP(port, cmd):
	try:
		s = socket(AF_INET,SOCK_DGRAM)
		s.bind(("0.0.0.0",int(sys.argv[1])))
		
		so = wratchet(s, int(sys.argv[1]))
		so.makeUDP()
		
		cmd = wratchet()
		cmd.makeCMD(sys.argv[2])
		
		manageConn(so,cmd)
	
		s.close()
	except:
		print("Error:  %s"%sys.exc_info()[0])
		sys.excepthook(sys.exc_info()[0],sys.exc_info()[1],sys.exc_info()[2])
	s.close()

### RAW socket, protocol of your choosing, -e
def elisternerRAW(protocol, cmd, port=0):
	try:
		s = socket(AF_INET,SOCK_RAW,protocol)
		so = wratchet(s)
		so.makeRAW()
		
		cmd = wratchet()
		cmd.makeCMD(cmd)
		
		manageConn(so,cmd)
	
		s.close()
	except:
		print("Error:  %s"%sys.exc_info()[0])
		sys.excepthook(sys.exc_info()[0],sys.exc_info()[1],sys.exc_info()[2])
	s.close()


LISTEN = False
HARDER = False
PROTO = 6  # TCP protocol number
RHOST = None
RPORT = None
LHOST = "0.0.0.0"
LPORT = 0
CMD = None
s = None
so = None
lso = None
if __name__ == "__main__":
  while (len(sys.argv) > 1):
	if (sys.argv[1] == '--help'):
        	syntax()
        	exit(1)
	elif (sys.argv[1] == "--sniff"):
		sys.argv.pop(1)
		RAW_SNIFF = True
	elif (sys.argv[1] == "-I"):
		sys.argv.pop(1)
		INTERACTIVE = True
	elif (sys.argv[1] == "-l"):
		sys.argv.pop(1)
		LISTEN = True
	elif (sys.argv[1] == "-L"):
		sys.argv.pop(1)
		LISTEN = True
		LISTENHARDER = True
	elif (sys.argv[1] == "-u"):
		sys.argv.pop(1)
		PROTO = 17
	elif (sys.argv[1] == "-e"):
		sys.argv.pop(1)
		CMD = sys.argv.pop(1)
	elif (sys.argv[1] == "-v"):
		sys.argv.pop(1)
		VERBOSE = True
	elif (sys.argv[1] == "-vv"):
		sys.argv.pop(1)
		VERBOSE = True
		VERYVERBOSE = True
	elif (sys.argv[1] == "-p"):
		sys.argv.pop(1)
		LPORT = int(sys.argv.pop(1))
	elif (sys.argv[1] == "-P"):
		sys.argv.pop(1)
		PROTO = sys.argv.pop(1)
		try:
			PROTO = int(PROTO)
		except:
			PROTO = getprotobyname(PROTO)

	elif (sys.argv[1] == "-w"):
		sys.argv.pop(1)
		WAIT = int(sys.argv.pop(1))
	elif (RHOST):
		RPORT = int(sys.argv.pop(1))
	else:
		RHOST = sys.argv.pop(1)
		
		

  try:
	GO = True
	while (GO):
		if (PROTO == 6): 
			s = socket()
			if (LISTEN):
				if (VERBOSE): 	print >>sys.stderr,("listening on [%s] %d ..."%(LHOST,LPORT))
				s.setsockopt(SOL_SOCKET,SO_REUSEADDR,1)
				s.bind((LHOST,LPORT))
				s.listen(10000)
				a,addy = s.accept()
				a.setblocking(False)
				a.setsockopt(SOL_SOCKET,SO_REUSEADDR,1)
				RA,RP = addy
				so = wratchet(a, LHOST,LPORT, RA, RP)
				if (VERBOSE):	print >>sys.stderr,("connect to [%s] from localhost.localdomain [%s] %d"%(s.getsockname(),RA,RP))


			else:
				if (VERBOSE):   print >>sys.stderr,("%s %s"%(RHOST,RPORT))
				s.connect((RHOST,RPORT))
				so = wratchet(s, LHOST,LPORT, RHOST,RPORT)
				
			
		elif (PROTO == 17): 
			s = socket(AF_INET,SOCK_DGRAM)
			so = wratchet(s, LHOST, LPORT, RHOST, RPORT, PROTO)
			so.makeUDP()
			s.bind(("0.0.0.0",LPORT))
			if (LISTEN):	
				if (VERBOSE): 	print >>sys.stderr,("listening on [%s] %d ..."%(LHOST,LPORT))
				while (not so.select(.1)): pass
			else:
				if (VERBOSE):   print >>sys.stderr,("%s %s"%(RHOST,RPORT))
				
				
			
		else: 
			s = socket(AF_INET,SOCK_RAW, PROTO)
			so = wratchet(s,LHOST,LPORT,RHOST,RPORT,PROTO)
			so.makeRAW()
			if (LISTEN):
				if (VERBOSE): 	print >>sys.stderr,("listening on [%s] protocol %d ..."%(LHOST,PROTO))
				while (not so.select(.1)): pass
			else:
				if (VERBOSE):   print >>sys.stderr,("%s %s"%(RHOST,PROTO))
	
		lso = wratchet()
		
		if (CMD):
			lso.makeCMD(CMD)
		else:
			lso.makeFILE(sys.stdin, sys.stdout)
			lso.isStdin = True
		
		manageConn(so,lso)
	
		so.close()
		lso.close()
	
		if (not LISTENHARDER):
			GO=False

  except:
	print("Error:  %s"%sys.exc_info()[0])
	sys.excepthook(sys.exc_info()[0],sys.exc_info()[1],sys.exc_info()[2])

  try:
	lso.close()
  except:
	pass

  try:
	so.close()
  except:
	pass


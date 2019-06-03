import socket,sys,select
def portscan(host, portstart=0, portstop=10000, verbose=False, nudge=False, timeout=.3):
    socket.setdefaulttimeout(timeout)
    ports=[]
    for x in xrange(portstart,portstop):
        try:
            s=socket.socket()
            s.connect((host,x))
            if verbose:
                print x
            ports.append(x)
        except Exception,e:
            if not str(e).startswith('(111,' ):
                print " ERROR AT PORT %d"%x
                x,y,z=sys.exc_info()
                print sys.excepthook(x,y,z)
    return ports

def nudge(sock=None, host=None, port=-1, polltimeout=10):
  output = ""
  try:
    if sock == None:
        sock = socket.socket()
        sock.connect((host,port))
    p = select.poll()
    p.register(sock.fileno(),3)
    r = p.poll(polltimeout)
    if r and r[0] and r[0][1] & 3:
        output += sock.recv(10000)
    else:
        sock.sendall('\n\n \n\n')
        r = p.poll(polltimeout)
        if r and r[0] and r[0][1] & 3:
            output += sock.recv(10000)
  except Exception, e:
    x,y,z = sys.exc_info()
    sys.excepthook(x,y,z)
  return output

        

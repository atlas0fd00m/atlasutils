#!/usr/bin/python
#
# client.py
#
"""
Simple SSL client, using blocking I/O
"""

from OpenSSL import SSL
import sys, os, select, socket


if len(sys.argv) < 3:
    print 'Usage: %s HOST PORT'%sys.argv[0]
    sys.exit(1)


#def verify_cert(conn, cert, errnum, depth, ok):
    ## crappy version scraped from example code... Unnecessary for 
    #print 'Got certificate: %s' % cert.get_subject()
    #return ok

def sendsock(sock,outinfo):
    print >>sys.stderr,(">> %s"%repr(outinfo))
    sock.sendall(outinfo)

def readsock(sock):
    readsomething = False
    readstuff= ""
    readsomething = True
    #print>>sys.stderr,("< ")
    try:
        readstuff += sock.recv(1024)
    except SSL.ZeroReturnError:
        print>>sys.stderr,("<< %s"%readstuff)
        return readstuff
            
    except SSL.Error:
        print 'Connection died unexpectedly'
        x,y,z=sys.exc_info()
        sys.excepthook(x,y,z)

ctx = SSL.Context(SSL.SSLv23_METHOD)
#basedir = os.path.dirname(sys.argv[0])
#if basedir == '':
    #basedir = os.curdir
#ctx.set_verify(SSL.VERIFY_PEER, verify_cert)
#ctx.use_privatekey_file (os.path.join(basedir, 'client.pkey'))
#ctx.use_certificate_file(os.path.join(basedir, 'client.crt'))
#ctx.load_verify_locations(os.path.join(basedir, 'CA.crt'))

# Set up client
sock = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
sock.connect((sys.argv[1], int(sys.argv[2])))


while 1:
    try:
        x,y,z = select.select([sys.stdin, sock],[],[],.1)
        #x,y,z = select.select([sys.stdin, sock],[],[],.1)
        if sys.stdin in x:
            #print>>sys.stderr,(">")
            line = sys.stdin.read(1000)
            if line != '':
                sendsock(sock,line)
        
        if sock in x:
            #print>>sys.stderr,("<")
            sys.stdout.write(sock.recv(1500))
            sys.stdout.flush()
        
    except SSL.ZeroReturnError:
        exit(0)
    except SSL.Error:
        print 'Connection died unexpectedly'
        x,y,z=sys.exc_info()
        sys.excepthook(x,y,z)
        break


sock.shutdown()
sock.close()

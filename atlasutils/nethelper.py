import sys,select

def interactive(sock):
    while True:
        x,y,z = select.select([sock,sys.stdin],[],[],.1)
        if sock in x:
            sys.stderr.write('.')
            input = sock.recv(1000)
            if len(input) == 0:
                break
            else:
                sys.stdout.write(input)
        if sys.stdin in x:
            sock.sendall(sys.stdin.read(1))



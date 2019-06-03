#server
import socket, select
s=socket.socket()
#s.setsockopt(socket.SOL_SOCKET,SO_REUSEADDR,1)
s.bind(('localhost',1366))
s.listen(100)
si,addy=s.accept()
si.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
si.send("This is a test server.  Totally oblivious to any other protocols, I'm a dummy.")


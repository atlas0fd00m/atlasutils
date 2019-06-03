#client
import socket, select
s=socket.socket()
s.connect(('localhost',1366))
select.select([s],[],[],2)
print s.recv(10000)

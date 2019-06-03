#!/usr/bin/env python

URL  = "/authurl"
USER = ""
PASSWD = ""

HOST = None
PARMS= "username=%s&password=%s" % (USER, PASSWD)

COMMONHDR = [ "", \
    "UserAgent: atlaswebhack v1.0"\
    ]

if HOST:
	COMMONHDR.append("Host: %s" % HOST)




COMMONHDR.append("Content-Length: %d\n"%len(PARMS))

POSTAUTH = "POST %s HTTP/1.0%s" % (URL, "\n".join(COMMONHDR))
GETAUTH  = "GET %s HTTP/1.0%s"  % (URL, "\n".join(COMMONHDR))

def authenticate():

def attack():

if __name__ == "__main__":
	authenticate()
	attack()



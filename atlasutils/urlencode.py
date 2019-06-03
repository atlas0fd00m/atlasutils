import re

ILLEGALCHARS = "[/%^\*()&#$!@\\\[\]]"

def urlencode(inp):
    outputline = ""
    matches = re.findall(ILLEGALCHARS, inp)
    inplen = len(inp)
    inpbuf = buffer(inp)
    offset = 0
    for match in matches:
        next = inp.find(match, offset)
        if next > -1:
            outputline += inpbuf[offset:next] + "%%%2x"%(ord(match))
            offset = next+1
        else:
            outputline += inpbuf[offset:]
            offset = inplen
    return outputline

urlencode('AAAAAaaaaaaaaa/%$#')


def urldecode(inp):
    outputline = ""
    inplen = len(inp)
    inpbuf = buffer(inp)
    offset = 0
    while offset < inplen:
        next = inp.find('%', offset)
        if next > -1:
            byte = int(inpbuf[next+1:next+3],16)
            outputline += inpbuf[offset:next] + chr(byte)
            offset = next+3
        else:
            outputline += inpbuf[offset:]
            offset = inplen
    return outputline

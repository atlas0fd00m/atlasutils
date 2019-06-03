from vtrace import *
import sys


HEAPSTART = None
def getConnectedChain(me, minimum=10):
    global HEAPSTART
    heapstart = 0
    heaplen = 0
    heapend = 0
    if HEAPSTART:
        heapstart = HEAPSTART[0]
        heaplen = HEAPSTART[1]
    else:
        for m in me.getMaps():
            if '[heap]' in m[3]:  
                heapstart = m[0]
                heaplen = m[1]
    heapptr = heapstart
    heapend = heapstart + heaplen
    finished = 0
    chunks = None
    #print("HEAPSTART: %x\t\t HEAPEND: %x\t\t HEAPLEN: %x"%(heapstart,heapend, heaplen))
    while heapptr < heapend and finished < minimum:
        heapptr += 4
        chunks = []
        finished = recurseConnectedChain(me, heapptr, heapend, chunks)
        #if finished > 1: print("Finished Tracing Path:  HEAP: %x\t\tLevels: %d"%(heapptr,finished))
        # HEAP address from maps should be aligned correctly
    if not HEAPSTART:
        HEAPSTART = (chunks[0],heaplen+heapstart-chunks[0])
    return chunks
    #HEAPCHAIN = (heapptr, finished, chunks)
    #return (heapptr, finished, chunks)

def recurseConnectedChain(me, address, end, chunks, finished=0):
    chunk = me.readMemoryFormat(address, "L")[0]  & 0xfffffffe
    chunks.append(address)
    if (chunk > 0 and not (chunk & 2) and chunk < end - address):
        #print ("Recursing %x, chunk = %x, nextaddress: %x, level %d"%(address, chunk, address+chunk, finished))
        try:
            #print " Calling Recurse again..."
            finished += (recurseConnectedChain(me, address+chunk, end, chunks))
        except Exception,e:
            print "ERROR: %s "%e
            return 1
    return finished +1

#findConnectedChain(me)

def findNextHeap(me, address):
    chain = getConnectedChain(me)
    for x in xrange(1,len(chain)):
        if chain[x] > address and chain[x-1] <= address:
            return chain[x]


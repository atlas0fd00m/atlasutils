#!/usr/bin/python -i

from atlasutils.vtraceutils import *
from atlasutils.vtraceheaputils import *
from atlasutils.smartprint import *
from atlasutils import *
#from disass3 import *
import struct
import time
from threading import *
"""
List of Badguy Targets to Watch:
strcpy()
strncpy()
strcat()
strncat()
sprintf()
scanf()
sscanf()
fscanf()
vfscanf()
vsprintf
vscanf()
vsscanf()
streadd()
strecpy()
strtrns()
memcpy()
memccpy()
mempcpy()
memmove()
memchr()
memrchr()
xgets()
fgets()

"""



BITS = 32
AddrFmt='L'
AddrBytes = BITS/8
AddrHeapMallocMask = -8
EXAMPLE_MEMORY_LENGTH = 24


def getHeapChunkDLMalloc(tracer, heapaddress):
    sz=0xffffffff
    heap,hlen,htyp,hname= me.getMap(heapaddress)
    endaddress = heap+hlen
    chunk=heap
    while sz != 0 and chunk < heapaddress and chunk < endaddress:
        #print XW(me,heap+off,8)
        sz = me.readMemoryFormat(chunk+4,"L")[0] & AddrHeapMallocMask
        chunk += sz
    return (chunk - sz, sz)   #had to overshoot to find it...

    
def getHeapLenDLMalloc(tracer, heapaddress):
    #sz = me.readMemoryFormat(chunk+4,"L")[0] & AddrHeapMallocMask
    #if sz < 1 or sz > 
    #
    #base, sz = getHeapChunkDLMalloc(tracer, heapaddress)
    return findNextHeap(tracer, heapaddress) - heapaddress
    
"""         Tracking HEAP is somewhat costly if the buffer is near the end
>>> t=time.time();getHeapLenDLMalloc(me,0x8250319); w=time.time(); print w-t
19687L
14.8094928265
>>> t=time.time();getHeapLenDLMalloc(me,0x8250319); w=time.time(); print w-t
19687L
11.0967998505
>>> t=time.time();getHeapLenDLMalloc(me,0x8250319); w=time.time(); print w-t
19687L
14.7216470242
>>> t=time.time();getHeapLenDLMalloc(me,0x8250319); w=time.time(); print w-t
19687L
14.8756971359
>>> t=time.time();getHeapLenDLMalloc(me,0x8250319); w=time.time(); print w-t
19687L
12.1300940514

"""


getHeapLen = getHeapLenDLMalloc

class VulnEvent(Exception):
    def __init__(self, trace, location, type, src=0, dest=0, len=0, destlen=0):
        self.location = location
        self.dest = dest
        self.src = src
        self.len = len
        self.destlen = destlen
        self.trace = trace
        self.data = ""
        self.message = "%s Event (%x): dest: %x <- src: %x, cpylen(%x) > destlen(%x)"%(type, location, dest, src, len, destlen)


class BOFException(VulnEvent):
    def __init__(self, trace, location, type, src=0, dest=0, len=0, destlen=0):
        VulnEvent.__init__(self, trace, location, type, src, dest, len, destlen)
        self.message = "%s Overflow (%x): dest: %x <- src: %x, len(%x) > destlen(%x) -- Potential Buffer Overflow."%(type, location, dest, src, len, destlen)

class BOFDifferingLengthException(VulnEvent):
    def __init__(self, trace, location, type, src=0, dest=0, len=0, destlen=0, prevdestlen=0):
        VulnEvent.__init__(self, trace, location, type, src, dest, len, destlen)
        self.prevdestlen = prevdestlen
        self.message = "%s Variation (%x): dest: %x <- src: %x, len(%x) > destlen(%x) -- Copy Length Differs (prev: %x)."%(type, location, dest, src, len, destlen, prevdestlen)


class TestBreakpointSubscriber():
    def __init__(self):
        self.threads = []
        self.queue = []
        self.cont = True
        self.events = {}
        self.maxthreads = 1
        for x in xrange(self.maxthreads):
            t = Thread(target=self.notifythread)
            t.setDaemon(True)
            t.start()
            self.threads.append(t)

    def __del__(self):
        self.cont = False
        for x in self.threads:
            x.stop()
        self.threads = []
        
    def notify(self, exception):
        try:
            exception.data = exception.trace.readMemory(exception.src, exception.len)
        except:
            errorhandler()
        self.queue.append(exception)
        
    def notifythread(self):
        while self.cont:
            try:
                work = self.queue.pop()
            except:
                time.sleep(.1)
                continue
            print >>stderr,("Notify: %s\n%s"%(work.message, hexText(work.data)))
            key = "%s:%s"%(work.location, work.dest)
            store = self.events.get(key, None)
            if store == None:
                store = []
            store.append(work)
            self.events[key] = store
        


class BreakpointPublisher(Breakpoint):
    """
    BreakpointPublisher is a subclass of vtrace's Breakpoint class, and provides the mechanisms required for generic event-publishing, such as subscribing, unsubscribing, and subscriber notification.
    """
    def __init__(self, address):
        Breakpoint.__init__(self, address)
        self.subscribers = []
    
    def subscribe(self, subscriber):
        """ subscribers are expected to implement a "notify(self, exception)" where exception is an object which stores pertinent info about the issue, preferably implementing __str__(self) to describe itself.
        """
        if (not subscriber in self.subscribers):
            self.subscribers.append(subscriber)
    
    def unsubscribe(self, subscriber):
        if (subscriber in self.subscribers):
            self.subscribers.remove(subscriber)
    
    def publish(self, exception):
        for e in self.subscribers: 
            e.notify(exception)
    
    
class BOFBreakpoint(BreakpointPublisher):
    """
    BOFBreakpoint is a subclass of BreakpointPublisher and provides assistance methods which should prove beneficial to all BOFBreaker implementations such as MemcpyBreaker and StrcpyBreaker.
    """
    def __init__(self, tracer, minlen=5, address = None, verbose = False, subscriber = TestBreakpointSubscriber()):
        BreakpointPublisher.__init__(self, address)
        self.tracker = {}
        self.variance = {}
        self.verbose = verbose
        self.minlen = minlen
        self.subscribe(subscriber)
    




class MemcpyBreaker(BOFBreakpoint):
    """  
    This class is currently only after:
      * stack overflows which reach ebp
      * calls where the cpylen is dynamic (ie, calls from the same line of code have a different)
      * heap overflows which reach the next heap node.
    
    Future versions may add in stack variable overflows using disass3 subroutine objects (which must be provided)
    This will allow you to catch overflows which only grown beyond their own length, allowing tampering with other stack variables
    """
    def __init__(self, tracer, minlen=5, address = None, verbose = False, subscriber = TestBreakpointSubscriber()):
        self.pltloc = address
        if (self.pltloc == None):
            if os.name=='posix':
                self.pltloc = tracer.parseExpression('libc.memcpy')
            elif os.name=='nt':
                self.pltloc = tracer.parseExpression('msvcr71.memcpy')
        BOFBreakpoint.__init__(self, tracer, minlen, self.pltloc, verbose, subscriber)
        tracer.addBreakpoint(self)
    
    
    def notify(self, event, trace):
        eip = trace.getProgramCounter()
        esp = trace.getRegisterByName('esp')
        ebp = trace.getRegisterByName('ebp')
        copylen = trace.readMemoryFormat((esp + 0xc),AddrFmt)[0]
        retptr  = trace.readMemoryFormat((esp + 0x0),AddrFmt)[0]
        dest    = trace.readMemoryFormat((esp + 0x4),AddrFmt)[0]
        src     = trace.readMemoryFormat((esp + 0x8),AddrFmt)[0]
        destlen = 0
        
        mmap = trace.getMap(dest)
        #print >>stderr,(mmap[3])
        if ('[stack]' == mmap[3]):
            
            destlen = findRET(trace, dest) - dest
            #print >>stderr,("%x"%destlen)
        elif ('[heap]' == mmap[3]):
            destlen = getHeapLen(trace, dest)
            #print >>stderr,("%x"%destlen)
        else:
            destlen = ebp - dest
        
        # If the copylen is greater than the length of our destination... 
        if (copylen > destlen):
            self.publish(BOFException(trace, retptr, 'memcpy(%s)'%mmap[3], src, dest, copylen, destlen))
        
        ### Track changes to copy length
        ### The basic idea is that changes in the copy length could indicate we have control over it.
        ### At this point, it makes the most sense to track dest-buffer/copy combinations, since different 
        ###   buffers may be copied at the same location.  Obviously the location is important, so we combine them.
        key = "%x:%x"%(retptr,dest)
        prevlen = self.tracker.get(key, None)
        if (prevlen == None):
            self.tracker[key] = copylen
        elif (prevlen != copylen):
            ### Let's keep track of the variations so we can pull them later.
            variance = self.variance.get(key, None)
            if variance == None:
                variance = []
                variance.append(copylen)
            elif copylen not in variance:
                variance.append(copylen)
            self.variance[key] = variance
            ### ALERT - Changing length from same call....
            self.publish(BOFDifferingLengthException(trace, retptr, 'memcpy', src, dest, copylen, destlen, prevlen))
        
        if (self.verbose):                              # If we're being Verbose, mention every break
            self.publish(VulnEvent(trace, retptr, 'memcpy', src, dest, copylen, destlen))














class StrncpyBreaker(BOFBreakpoint):
    """  
    This class is currently only after:
      * stack overflows which reach ebp
      * calls where the cpylen is dynamic (ie, calls from the same line of code have a different)
      * heap overflows which reach the next heap node.
    
    Future versions may add in stack variable overflows using disass3 subroutine objects (which must be provided)
    This will allow you to catch overflows which only grown beyond their own length, allowing tampering with other stack variables
    """
    def __init__(self, tracer, minlen=5, address = None, verbose = False, subscriber = TestBreakpointSubscriber()):
        self.pltloc = address
        if (self.pltloc == None):
            if os.name=='posix':
                self.pltloc = tracer.parseExpression('libc.strncpy')
            elif os.name=='nt':
                self.pltloc = tracer.parseExpression('msvcr71.strncpy')
        BOFBreakpoint.__init__(self, tracer, minlen, self.pltloc, verbose, subscriber)
        tracer.addBreakpoint(self)


    def notify(self, event, trace):
        eip = trace.getProgramCounter()
        esp = trace.getRegisterByName('esp')
        ebp = trace.getRegisterByName('ebp')
        retptr  = trace.readMemoryFormat((esp + 0x0), AddrFmt)[0]
        dest    = trace.readMemoryFormat((esp + 0x4), AddrFmt)[0]
        src     = trace.readMemoryFormat((esp + 0x8), AddrFmt)[0]
        copylen = trace.readMemoryFormat((esp + 0xc), AddrFmt)[0]
        destlen = 0
        if copylen >= self.minlen: 
            mmap = trace.getMap(dest)
            if ('[stack]' == mmap[3]):
                # Virtual %EBP, since %EBP likely can't be trusted....
                destlen = findRET(trace, dest) - dest
            elif ('[heap]' == mmap[3]):
                destlen = getHeapLen(trace, dest)
                
            # Check for previous hits
            if (self.tracker.get(retptr, None) == None):
                self.tracker[retptr] = copylen
            elif (self.tracker[retptr] != copylen):
                self.publish(BOFDifferingLengthException(trace, retptr, 'strncpy', src, dest, copylen, destlen))### ALERT - Changing length from same call....
            
            if (copylen >= maxlen):     # If the copylen is greater than the length of our destination... 
                self.publish(BOFException(trace, retptr, 'strncpy', dest, src, copylen, destlen))
            
            ### Track Changes in copy length
            ### The basic idea is that changes in the copy length could indicate we have control over it.
            ### At this point, it makes the most sense to track dest-buffer/copy combinations, since different 
            ###   buffers may be copied at the same location.  Obviously the location is important, so we combine them.
            key = "%x:%x"%(retptr,dest)
            prevlen = self.tracker.get(key, None)
            if (prevlen == None):
                self.tracker[key] = copylen
            elif (prevlen != copylen):
                variance = self.variance.get(key, None)
                if variance == None:
                    variance = []
                    variance.append(copylen)
                elif copylen not in variance:
                    variance.append(copylen)
                self.variance[key] = variance
                self.publish(BOFDifferingLengthException(trace, retptr, 'memcpy', src, dest, copylen, destlen, prevlen))### ALERT - Changing length from same call....
                
        if (self.verbose):          # If we're being Verbose, mention every call to it
            self.publish(VulnEvent(trace, retptr, 'strncpy', src, dest, copylen, destlen))














class StrcpyBreaker(BOFBreakpoint):
    """  
    This class is currently only after:
      * stack overflows which reach ebp
      * calls where the cpylen is dynamic (ie, calls from the same line of code have a different)
      * heap overflows which reach the next heap node.
    
    Future versions may add in stack variable overflows using disass3 subroutine objects (which must be provided)
    This will allow you to catch overflows which only grown beyond their own length, allowing tampering with other stack variables
    """
    def __init__(self, tracer, minlen=5, address = None, verbose = False, subscriber = TestBreakpointSubscriber()):
        self.pltloc = address
        if (self.pltloc == None):
            if os.name=='posix':
                self.pltloc = tracer.parseExpression('libc.strcpy')
            elif os.name=='nt':
                self.pltloc = tracer.parseExpression('msvcr71.strcpy')
        BOFBreakpoint.__init__(self, tracer, minlen, self.pltloc, verbose, subscriber)
        tracer.addBreakpoint(self)


    def notify(self, event, trace):
        eip = trace.getProgramCounter()
        esp = trace.getRegisterByName('esp')
        ebp = trace.getRegisterByName('ebp')
        retptr  = trace.readMemoryFormat((esp + 0x0), AddrFmt)[0]
        dest    = trace.readMemoryFormat((esp + 0x4), AddrFmt)[0]
        src     = trace.readMemoryFormat((esp + 0x8), AddrFmt)[0]
        copylen = trace.readMemoryFormat((esp + 0xc), AddrFmt)[0]
        destlen = 0
        address = 0
        
        if copylen >= self.minlen:
            mmap = trace.getMap(dest)
            if ('[stack]' == mmap[3]):
                # Virtual %EBP, since %EBP likely can't be trusted....
                destlen = findRET(trace, dest) - dest
            elif ('[heap]' == mmap[3]):
                # Platform-dependent architecture
                destlen = getHeapLen(trace, dest)
            
            # This is strcpy, source length is important
            mmap = trace.getMap(src)
            if ('stack' in mmap[3]):
                # Virtual %EBP, since %EBP obviously can't be trusted....
                srclen = findRET(trace, src) - src
            elif ('heap' in mmap[3]):
                srclen = getHeapLen(trace, src)

            ## Check for previous hits
            #if (self.tracker.get(retptr, None) == None):
                #self.tracker[retptr] = copylen
            #elif (self.tracker[retptr] != copylen):
                #self.publish(BOFDifferingLengthException(retptr, 'strncpy', dest, src, copylen, destlen))### ALERT - Changing length from same call....
            
            if (srclen >= destlen):     # If the copylen is greater than the length of our destination... 
                self.publish(BOFException(trace, retptr, 'strncpy', src, dest, srclen, destlen))
            
            ### Track Changes in copy length
            ### The basic idea is that changes in the copy length could indicate we have control over it.
            ### At this point, it makes the most sense to track dest-buffer/copy combinations, since different 
            ###   buffers may be copied at the same location.  Obviously the location is important, so we combine them.
            key = "%x:%x"%(retptr,dest)
            prevlen = self.tracker.get(key, None)
            if (prevlen == None):
                self.tracker[key] = copylen
            elif (prevlen != copylen):
                variance = self.variance.get(key, None)
                if variance == None:
                    variance = []
                    variance.append(copylen)
                elif copylen not in variance:
                    variance.append(copylen)
                self.variance[key] = variance
                self.publish(BOFDifferingLengthException(trace, retptr, 'memcpy', src, dest, srclen, destlen, prevlen))### ALERT - Changing length from same call....
                
        if (self.verbose):          # If we're being Verbose, mention every call to it
            self.publish(VulnEvent(trace, retptr, 'strncpy', src, dest, srclen, destlen))



#######################################################################################################################
me = getTrace()
mcb = None
scb = None
sncb = None

if __name__ == "__main__" and len(argv) > 1:
    if len(argv) == 3:
        me.attach(int(argv[2]))
    elif len(argv) == 2:
        me.execute(argv[1])
    else:
        print ("Syntax:   %s <binary> [pid]"%argv[0])
        exit(1)
    #verbose = True
    me.registerNotifier(vtrace.NOTIFY_BREAK, VerboseNotifier())
    
    t = TestBreakpointSubscriber()
    mcb = MemcpyBreaker(me, verbose=verbose, subscriber = t)
    scb = StrcpyBreaker(me, verbose=verbose, subscriber = t)
    sncb = StrncpyBreaker(me, verbose=verbose, subscriber = t)
    me.setMode("RunForever", True)
    me.setMode("NonBlocking", True)
    me.run()
    """
    >>> me.searchMemoryRange('\x8bL$\x0c\x89\xf8\x8b|$\x04\x89\xf2\x8bt$\x08\xfc\xd1\xe9s\x01\xa4\xd1\xe9s\x02f\xa5\xf3\xa5\x89\xc7\x89\xd6\x8bD$\x04\xc3\x90', 0xb7b91000,0x13b000)
    [3082814256L]
    """
    
"""
###  Studying Opcodes
from atlasutils.smartprint import *
from atlasutils.disassutils import *

lens = {}
for x in range(256):
  op=Opcode('\xff%cAAAAAAA'%x)
  if op.printOpcode(0)[0] == 'c':
    lens[op.off] = op
    print "%d:  %s  %s"%(x,hexText(op.data),op.printOpcode(0))


for x in lens.keys():
  print "%d:  %s  %s"%(x,hexText(lens[x].data),lens[x].printOpcode(0))




HEAPCRAWLER:
sz=0xfffff
off=0
heap= 134557696
while sz != 0:
    print XW(me,heap+off,8)
    sz = me.readMemoryFormat(heap+off+4,"L")[0]
    off += (sz &0xfffffffe)

"""
import sys

ERROR_COUNT=0

def errorhandler():
    global ERROR_COUNT
    ERROR_COUNT += 1
    x,y,z = sys.exc_info()
    sys.excepthook(x,y,z)
    

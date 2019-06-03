from sys import *
from vtrace import *
from select import select
from vtrace.breakpoints import *
from atlasutils.smartprint import *
from atlasutils import *
try:
    from atlasutils.disassutils import *
    from disassemble import *
except:
    print exc_info()
    print "Initializing vtraceutils *without* libdisassemble... this could be bad."

BITS = 32
AddrFmt='L'
AddrBytes = BITS/8
AddrHeapMallocMask = -8
EXAMPLE_MEMORY_LENGTH = 24

def setBits(bits):
    BITS=bits
    AddrFmt=('B','H',None,'L',None,None,None,'Q')[BITS/8]
    AddrBytes = BITS/8
    AddrHeapMallocMask = -8
    EXAMPLE_MEMORY_LENGTH = 24


class DisplayBreaker(Breakpoint):
    def __init__(self, address):
        Breakpoint.__init__(self, address)
        self.address = address
        
    def notify(self, event, trace):
        trace.running = False
        print "PID: %d hit break: %s" % (trace.pid, hex(self.address))
        select([],[],[],1)
        print printStuff(trace)
        print XI(trace, self.address, 5)
        
class StackSysCallBreaker(Breakpoint):
    def __init__(self, tracer, syscallname = 'libc.memcpy'):
        address = tracer.parseExpression(syscallname)
        Breakpoint.__init__(self, address)
    def notify(self, event, trace):
        esp = trace.getRegisterByName('esp')
        SmartPrint(trace.readMemory(esp, 200))

##### SET BREAKPOINTS FOR ALL "cmp %eax, *"
def breakOnAll(asmdict, opstring = "cmp %eax", trace = None):
    """
    searches through the assembly code (in the form of the dict asmdict) and adds vtrace.Breakpoints for each occurrence of the "opstring"
    asmdict:   keys = "<hexaddress>",   values = "<opcode string>"
        eg.   asmdict.setdefault("0x401443", "cmp %eax, $0x12345")
    
    returns an array of keys where the values match.
    """
    cmps = []
    keys = asmdict.keys()
    values = asmdict.values()
    for i in range(len(values)):
        if (values[i][:len(opstring)] == opstring):
            print(" Adding breakpoint for  %s: %s"%(keys[i],values[i])) 
            cmps.append(keys[i])
            if trace: trace.addBreakpoint(Breakpoint(int(keys[i],16)))
    return (cmps)


def brk(me):
    me.running=True
    for t in me.getThreads():
        me.sendBreak()
    me.running=False
    

def stepi(me):
    origThread = me.getMeta('ThreadId')
    for t in me.getThreads():
        me.selectThread(t)
        try:
            me.stepi()
            print "thread %8d: %x"%(t,me.getProgramCounter())
        except Exception,e:
            print "thread %8d: ERROR: %s"%(t, e)
    me.selectThread(origThread)

def prettystepi(me, outfile = stderr):
    origThread = me.getMeta('ThreadId')
    for t in me.getThreads():
        me.selectThread(t)
        me.stepi()
        eip = me.getProgramCounter()
        print >>outfile,("thread %8d: %x   (%s)"%(t,eip,me.getSymByAddr(eip)))
    me.selectThread(origThread)

def eips(me):
    origThread = me.getMeta('ThreadId')
    for t in me.getThreads():
        me.selectThread(t)
        print "thread %8d: %x"%(t,me.getProgramCounter())
    me.selectThread(origThread)









LOT_STRINGOUTPUT = "s"
LOT_INSTRUCTIONOUTPUT = "i"
LOT_HEXOUTPUT = "x"


def liveOrganTransplant(pidortrace, memloc, count = None, style = 'i'):
    output = ""
    if type(memloc) == str:  
        if memloc.lower().find('x') > -1:
            memloc = int(memloc,16)
        else:
            memloc = int(memloc)
    if type(count) == str:
        if count.lower().find('x') > -1:
            count = int(count,16)
        else:
            count = int(count)

    if (type(pidortrace) == int):
        trace = atlasutils.vtraceutils.getTrace()
        trace.attach(pidortrace)
    else:
        trace = pidortrace
    if style == LOT_STRINGOUTPUT:
        output = atlasutils.vtraceutils.XS(trace, memloc, count)
    elif style == LOT_HEXOUTPUT:
        output = atlasutils.vtraceutils.XW(trace, memloc, count)
    else:
        output = atlasutils.vtraceutils.XI(trace, memloc, count)
    if (type(pidortrace) == int):
        trace.detach()
    return output




locs = {}
def traceme(me, untilop=None, untileip=None, untilreg=('eax',None), locs = {}, printTrace=None, printAllThreads=False, triggerOnAnyThread = True, out=stdout, err=stderr, disasstrace=False):
    """
    So many options, let's see if we can explain some of them.
        me                  - Vtrace object to trace
            If specified, the following 'until-" options will cause the trace to terminate.  This can be for any thread, or just the original thread, depending on the value of 'triggerOnAnyThread'
        untilop             - a string that is checked against the current opcode for all threads (or just one)
        untileip            - a number checked against the program counter
        untilreg            - a tuple ('eax', value) where a register is value-checked
        
        locs                - keeps track of jmps/calls and targets, as well as the hit-count.  Hand in if you wish, or use the default of {}
        printTrace          - prints out a pretty list of 'locs' in order
        printAllThreads     - cycle through all threads with "printStuff(me)"
        triggerOnAnyThread  - Apply 'until-' clauses to any thread.  If False, only the original thread will be compared to stop tracing.
    """
    if (not (printTrace or untilop or untileip or untilreg[1])):
        printTrace=True #set the default.  If none specified, print if no until-s.  If there are until-s, default to no printing unless specified
        
    print >>err,("TRACING EXECUTION... Press CTRL-C to stop.  Accounting will be stored in 'locs' and returned")
    origThread = me.getMeta('ThreadId')
    last=me.getProgramCounter()
    cont=True
    eip=None
    op=None
    disasstracer = None
    for x in me.getThreads():
        locs[x] = {}
    if disasstrace:
        disasstracer = {}
    try:
        while cont:
            t = me.getThreads()
            try:
                for i in t:
                    me.selectThread(i)
                    me.stepi()
                    if (printAllThreads or i == origThread):
                        print >>out,printStuff(me)
                        print >>out, t
                        
                        
                    if (triggerOnAnyThread or i == origThread):
                        eip=me.getProgramCounter()
                        op=Opcode(me.readMemory(eip, 14))
                        if disasstrace:
                            ### Let's save some state information.  This gets big fast
                            cur = disasstracer.get(eip, [op.printOpcode(0)])
                            if op.source:
                                recurseOperand(me, op.source, cur, i)
                                    
                            if op.dest:
                                recurseOperand(me, op.dest, cur, i)
                                    
                            if op.aux:
                                recurseOperand(me, op.aux, cur, i)
                                    
                            disasstracer[eip] = cur
                        if (abs(eip - last) > 9):
                            locs[i][last] = (locs[i].get(last,0)) + 1
                            locs[i][eip] = (locs[i].get(eip,0)) + 1
                        last=eip
                        
                        if (untilop):
                                #if (untilop in getinst(me)):
                                if (op.opcode in untilop):
                                    cont=False
                                    break
                        if (untileip):
                                if (untileip == me.getProgramCounter()):
                                    cont=False
                                    break
                        if (untilreg[1]):
                                if (me.getRegisters()[untilreg[0]] == untilreg[1]):
                                    cont=False
                                    break
            except KeyboardInterrupt, k:
                me.selectThread(origThread)
                break
            except:
                print >>stderr,("**************======== Opcode Not Printed... (bad or not supported?) ========**************")
                x,y,z = exc_info()
                excepthook(x,y,z)
            
            
            
    except KeyboardInterrupt, e:
        print >>err,("Trace Complete.  Look at 'locs'")
    if printTrace:
        printLocs(locs, out)
    if disasstrace:
        return disasstracer
    return locs

def recurseOperand(me, oper, cur, i):
    if (isinstance(oper, Expression)):
        #  Expressions have:  base.index, base.base
        if oper.disp:
            recurseOperand(me, oper.disp, cur, i)
        if oper.base:
            recurseOperand(me, oper.base, cur, i)
    if (isinstance(oper, Register)):
        #  Registers have 'name' which should fit into vtrace nicely
        cur.append("(thd%d)%s=%x"%(i, oper.name, me.getRegisterByName(oper.name)))
    elif (isinstance(oper, SIB)):
        if oper.base:
            recurseOperand(me, oper.base, cur, i)
        if oper.index:
            recurseOperand(me, oper.index, cur, i)
            
def getOperandValue(trace, opcode, operand, eip):
        dereference = False
        add = ""
        numaddr = 0
        source = operand
        if isinstance(source, SIB):
            if source.index:
                numaddr += (souce.index * source.scale)
            if source.base:
                source = source.base
            #print >>outfile,("DEBUG-sib: %x"%numaddr)
        if isinstance(source, Expression):
            if source.disp:
                numaddr += source.disp.value
            if source.base:
                source = source.base
            dereference = True
            #print >>outfile,("DEBUG-expr: %x"%numaddr)
        if isinstance(source, SIB):
            if source.index:
                numaddr += (souce.index * source.scale)
            if source.base:
                source = source.base
            #print >>outfile,("DEBUG-sib: %x"%numaddr)
        if isinstance(source, Register):
            reg = source.name
            mask = 0xffffffff       # 32 bit only
            if reg[0] != 'e' and reg[1] in ['l','h','x']:       # TOTALLY libdisassemble-centric, as it assumes lowercase letters
                if reg[1] == 'x':
                    mask = 0xffff
                elif reg[1] == 'l':
                    mask = 0xff
                elif reg[1] == 'h':
                    mask = 0xff00
                reg = 'e%cx'%reg[0]                             # vtrace doesn't like al/ah and possibly ax
            numaddr += (trace.getRegisterByName(reg) & mask)
            #print >>outfile,("DEBUG-reg: %x"%numaddr)
        elif isinstance(source, Address):
            numaddr += source.value
            if source.relative:
                numaddr += eip + opcode.off
            #print >>outfile,("DEBUG-addr: %x"%numaddr)
        if dereference:
            try:
                numaddr = struct.unpack("L",me.readMemory(numaddr, 4))[0]
                #print >>outfile,("DEBUG-deref: %x"%numaddr)
            except:
                #print >>outfile,("DEBUG-deref-except: %x"%numaddr)
                #print >>stderr,("DEBUG-deref-except: %x"%numaddr)
                pass
                
        return numaddr
    


def printLocs(locs, out=stdout):
    keys = locs.keys()
    keys.sort()
    for t in locs.keys(): 
        lkeys = locs[t].keys()
        lkeys.sort()
        for i in lkeys:
            print >>out,("(Thread %d): %x:%d"%(t, i, locs[t][i]))


def gotoOpcode(me, inbtwn=False, srch=['call'], file = stdout):
    """
    stepi() this thread until the opcode is found in srch
    This is single-threaded only at this point.  Only the current thread will be incremented. 
    """
    output = ""
    GO = True
    PRINT = True
    while (GO):
      for t in me.getThreads():
        me.selectThread(t)
        me.stepi()
        p = Opcode(me.readMemory(me.getProgramCounter(),14))
        if (inbtwn or PRINT): 
            file.write("\neip: %.08x: %s\n"%(me.getProgramCounter(),getinst(me)))
            PRINT=False
        for i in srch:
            if (p.opcode == i): GO = False

def walkTheLine(me, VERBOSE = False, file = stdout):
    while (True):
        gotoOpcode(me, VERBOSE, ['call'], file)
        p = Opcode(me.readMemory(me.getProgramCounter(),14))
        file.write(printStuff(me))
        #file.write(("%x: %s"%(me.getProgramCounter(),p.printOpcode("ATT")))

def getinst(me):
    eip=me.getProgramCounter()
    p = Opcode(me.readMemory(eip,14))
    return p.printOpcode("ATT", eip)


def si(me):
    me.stepi()
    print printStuff(me)


def ni(me):
    eip = me.getProgramCounter()
    #print >>outfile,("debug: %x"%self.eip)
    op = Opcode(me.readMemory(eip, 18))
    if op.opcode[:2] == "ca":
        baddr = eip+op.off
        brk = OneTimeBreak(baddr)
        #print >>outfile,("\t\t Going Remote...  Setting Breakpoint at %x"%(baddr))
        me.addBreakpoint(brk)
        me.run()
        #print repr(me)
        #me.removeBreakpoint(brk)
    else:
        me.stepi()
    print printStuff(me)

            

def XW(tracer, address, length = 32, dwperline = 8):
    output = ""
    for i in range(length):
        if (i % dwperline == 0):
            output += "%.08x:\t "%(address+(i*4))
        bs = tracer.readMemory(address+(i*4),4)
        for x in range(3, -1,-1):
            output += "%.02x"%(ord(bs[x]))
        if ((i+1) % dwperline == 0):
            output += "\n"
        else:
            output += "  "
    return output
        


def XI(tracer, address, length = 20, mode=32):
    output = ""
    offset = 0
    last = None
    prev = None
    p = {}
    for i in range(length):
        buffer = buffer = tracer.readMemory(address+offset,14)
        prev = last
        last = p
        try:
            p = Opcode(buffer)
        except:
            p.opcode = "ERROR: %s"%exc_info()[0]
            p.off = 1
            
        bytes = ""
        for i in buffer[:p.getSize()]:
            bytes += "%.02x "%ord(i)
        
        output += "%x: %30s\t %s\n"%((address+offset),bytes,p.printOpcode("AT&T",address+offset))
        if not p:
            break
        offset += p.getSize()
    return output

def XS(tracer, address, length=1, BUFFLEN=16):
    output = "%x: "%address
    offset = 0
    for i in range(length):
        eol = False
        while not eol:
            buffer = tracer.readMemory(address+offset,BUFFLEN)
            where = buffer.find("\x00")
            if (where>-1):
                offset += 1+where
                output += "%s\n%x: "%(buffer[:where], address+offset)
                eol = True
            else:
                offset += BUFFLEN
                output += buffer
    return output

REG_EAX = 0
REG_ECX = 1
REG_EDX = 2
REG_EBX = 3
REG_ESI = 4
REG_EDI = 5
REG_EIP = 6
REG_ESP = 7
REG_EBP = 8    
def printStuff(me, eachThread=False, width=8):
    output = ""
    iterate = [me.metadata['ThreadId']]
    if eachThread:
        iterate = me.getThreads()
    
    for t in iterate:
        frame = {'ebp': me.getRegisterByName("ebp"), 'esp': me.getRegisterByName("esp"),
                 'eax': me.getRegisterByName("eax"), 'ebx': me.getRegisterByName("ebx"),
                 'ecx': me.getRegisterByName("ecx"), 'edx': me.getRegisterByName("edx"),
                 'esi': me.getRegisterByName("esi"), 'edi': me.getRegisterByName("edi"),
                 'eip': me.getProgramCounter() }
        
        output += "\nThreadId:\t %d"%(t)
        output += "\n%esp: " + "(%x)\n" % frame.get('esp')
        try:
            output += XW(me, frame.get('esp'), 32, width)
        except:
            output += "ERROR READING FROM MEMORY AT %x\n"%frame.get('esp')
        
        output += "\n%ebp-92: " + "(%x)\n" % frame.get('esp')
        try:
            output += XW(me, frame.get('ebp')-92, 32, width)
        except:
            output += "ERROR READING FROM MEMORY AT %x\n"%(frame.get('ebp')-92)
        
        for i in ['eax','ecx','edx','ebx','esi','edi']:
            output += "%s: %.08x\t"%(i,frame.get(i))
        
        cmd = me.getSymByAddr(frame['eip'])
        output += "\neip: %.08x: %s\t\t\t%s"%(frame.get('eip'), getinst(me), cmd)
        output += "\n\t(%8x (%x): %d  %s)"%me.getMemoryMap(frame['eip'])
    return output


def atch(procname, me = getTrace(), procno = None):
  for proc in me.ps() :
    if (proc[1].split(" ")[0].find(procname) >-1):
      print ("Attaching to %d: %s"%(proc[0],proc[1]))
      try:
        me.attach(proc[0])  
        me.registerNotifier(vtrace.NOTIFY_ALL, VerboseNotifier())
        print("isRunning: %s\t\tisAttached: %s"%(me.isRunning(),me.isAttached()))
        print("Threads: %s"%(str(me.getThreads())))
        bt(me)
        return me
      except:
        print("Error attaching to pid:")
        print(proc)
        excepthook(exc_info()[0], exc_info()[1],exc_info()[2])
  return None

def bt(me):
    print("Stack Trace: (current thread)")
    for i in me.getStackTrace(): 
        print "%x : %x"%i
        

def findRET(trace, stackptr = 0):
    """
    findRET() traces up the stack searching for the previous RET address.  By default, findRET assumes that this is called from a breakpoint immediately at a system call before the stack is modified (ie, we assume there is a RET at %ESP so we skip ahead four bytes)
    If you hand in the stack pointer, this will find the RET value preceding that.
    """
    try:
        cont = True
        if stackptr == 0:
            stackptr = trace.getRegisterByName('esp')
        orig = stackptr
        stderr.write("Call to findRET (0x%x) "%stackptr)
        while cont:
            stackptr += 1#4
            if stackptr - orig > 1000:
                trace.setMode("RunForever", False)
            address = trace.readMemoryFormat(stackptr, AddrFmt)[0]
            mmap = trace.getMemoryMap(address)
            # valid address in an executable memory map?
            if mmap != None and mmap[2]&1:   
                #bytes just before the RET address(the opcode before, should be call)
                buf = buffer(trace.readMemory(address-8, 24))
                BUFLEN = 8
                for x in xrange(BUFLEN,0,-1):
                    opchar = buf[x]
                    #stderr.write("  %x%x  "%(x,ord(opchar)))
                    if (opchar == '\xff' and (ord(buf[x+1])>>4) & 3 == 1) or opchar == '\xe8' or opchar == '\x9a':
                        #print >>stderr,(hexText(buf[x:]))
                        op = Opcode(buf, x)
                        #stderr.write("*(%x:%x:%s:%d+%d=%d)\n"%(stackptr,address, op.opcode, op.getSize(), x,BUFLEN+1))
                        #if the length is correct and it's a call....  take our win... in one of two ways
                        if (op.opcodetype == opcode86.INS_CALL and op.getSize() + x == BUFLEN): 
                            if (op.source.opertype == 1 or op.source.opertype == 3):  #OPER_REGISTER or OPER_EXPRESSION
                                return stackptr
                            else:
                                #  recurses the Operand information to return a real value
                                target = getOperandValue(trace, op, op.source, address-op.off)  
                                #print >>stderr,("\n"+op.printOpcode(0)+"\n%x : %x"%(address, target))
                                mmap = trace.getMemoryMap(target)
                                if mmap != None and "stack" not in mmap[3] :        #  Is it a valid address?
                                    # Possibly Check the Target of the call
                                    #   * Does it point to this address or a opcode for a jmp to this address?
                                    #       Unfortunately, this is costly and not entirely accurate
                                    print >>stderr,("foundRET: (s/r/c)\t%x:%x:%x (%s - %s)\n"%(stackptr,address,target, op.printOpcode(0, address-10+x), trace.getSymByAddr(target)))
                                    return stackptr
                        else:
                            pass
                            #stderr.write("--%d--%d--"%(op.opcodetype,opcode86.INS_CALL))
            else:
                stderr.write(".")
    except:
        errorhandler()

"""
trace=me
esp = trace.getRegisterByName('esp')
op=None
#### loop through RET and see what goes where, and print the opcode preceeding ret
try:
    while True:
        address = findRET(me,esp)
        buf = trace.readMemory(address-10, 20)      #bytes just before the RET address(the opcode before, should be call)
        esp = address
except:
    pass
"""
import sys

ERROR_COUNT=0

def errorhandler():
    global ERROR_COUNT
    ERROR_COUNT += 1
    x,y,z = sys.exc_info()
    sys.excepthook(x,y,z)
    

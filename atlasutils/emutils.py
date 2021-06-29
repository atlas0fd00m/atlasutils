#!/usr/bin/env python
import cmd
import sys
import time
import struct
import struct
import traceback

import envi
import envi.memory as e_m
import envi.expression as e_expr
import envi.memcanvas as e_memcanvas

import envi.archs.i386 as e_i386
import envi.archs.amd64 as e_amd64

import visgraph.pathcore as vg_path
from binascii import hexlify, unhexlify


SNAP_NORM = 0
SNAP_CAP = 1
SNAP_DIFF = 2
SNAP_SWAP = 3

PEBSZ = 4096
TEBSZ = 4096

def parseExpression(emu, expr, lcls={}):
    '''
    localized updated expression parser for the emulator at any state
    '''
    if hasattr(emu, 'vw'):
        lcls.update(emu.vw.getExpressionLocals())
    lcls.update(emu.getRegisters())
    return e_expr.evaluate(expr, lcls)

import vivisect.impemu.monitor as v_i_monitor
class TraceMonitor(v_i_monitor.AnalysisMonitor):
    def __init__(self, traces=None):
        if traces is None:
            traces = {}
        self.traces = traces

    def prehook(self, emu, op, starteip):
        tdata = self.traces.get(starteip)
        if tdata is None:
            return

        try:
            print(repr(eval(tdata)))
        except Exception as e:
            print("TraceMonitor ERROR at 0x%x: %r" % (starteip, e))

testemu = None
call_handlers = {}
def runStep(emu, maxstep=1000000, follow=True, showafter=True, runTil=None, pause=True, silent=False, finish=0, tracedict=None, verbose=False, guiFuncGraphName=None):
    global testemu

    if testemu is None or testemu.emu != emu:
        testemu = TestEmulator(emu, verbose=verbose, guiFuncGraphName=guiFuncGraphName)
        testemu.call_handlers.update(call_handlers)
    
    testemu.runStep(maxstep=maxstep, follow=follow, showafter=showafter, runTil=runTil, pause=pause, silent=silent, finish=finish, tracedict=tracedict)


def readString(emu, va, CHUNK=50):
    off = 0
    out = [ emu.readMemory(va + off, CHUNK) ]
    while b'\0' not in out[-1]:
        off += CHUNK
        data = emu.readMemory(va + off, CHUNK)
        out.append(data)

    data = b''.join(out)

    return data[:data.find(b'\0')]

prehilite = '\x1b[7m'
posthilite = '\x1b[27m'
def compare(data1, data2):
    size = (len(data1), len(data2))[len(data1) > len(data2)]

    out1 = []
    out2 = []
    lastres = True
    for x in range(size):
        if data1[x] != data2[x]:
            if lastres:
                out1.append(prehilite)
                out2.append(prehilite)
            lastres = False
        else:
            if not lastres:
                out1.append(posthilite)
                out2.append(posthilite)
            lastres = True

        out1.append(data1[x:x+1].hex())
        out2.append(data2[x:x+1].hex())
   
    if len(data1) > len(data2):
        out1.append(data1[x:].hex())
    elif len(data1) > len(data2):
        out2.append(data2[x:].hex())
    
    if not lastres:
        out1.append(posthilite)
        out2.append(posthilite)

    print(''.join(out1))
    print(''.join(out2))


#######  replacement functions.  can set these in TestEmulator().call_handlers 
#######  to execute these in python instead of the supporting library
#######  can also be run from runStep() ui to execute the replacement function
def getLibcCallConv(emu):
    if hasattr(emu, 'vw') and emu.vw is not None:
        ccname = emu.vw.getMeta('DefaultCall')
        cconv = emu.getCallingConvention(ccname)
        return ccname, cconv

    return emu.getCallingConventions()[0]

def memset(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    cconv.allocateReturnAddress(emu)    # this assumes we've called
    dest, char, count = cconv.getCallArgs(emu, 3)

    data = ('%c' % char) * count
    emu.writeMemory(dest, data)
    print(data)
    cconv.deallocateCallSpace(emu, 0, 0)
    return data

def memcpy(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    cconv.allocateReturnAddress(emu)    # this assumes we've called
    dest, src, length = cconv.getCallArgs(emu, 3)
    data = emu.readMemory(src, length)
    emu.writeMemory(dest, data)
    print(data)
    cconv.setReturnValue(emu, dest)
    cconv.deallocateCallSpace(emu, 0)

    return data

def strncpy(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    cconv.allocateReturnAddress(emu)    # this assumes we've called
    dest, src, length = cconv.getCallArgs(emu, 3)
    data = emu.readMemory(src, length)
    nulloc = data.find(b'\0')
    if nulloc != -1:
        data = data[:nulloc]
    emu.writeMemory(dest, data)
    print(data)
    cconv.setReturnValue(emu, dest)
    cconv.deallocateCallSpace(emu, 0)
    return data

def strcpy(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    cconv.allocateReturnAddress(emu)    # this assumes we've called
    dest, src = cconv.getCallArgs(emu, 2)
    data = readString(emu, src) + b'\0'
    emu.writeMemory(dest, data)
    print(data)
    cconv.setReturnValue(emu, dest)
    cconv.deallocateCallSpace(emu, 0)
    return data

def strcat(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    cconv.allocateReturnAddress(emu)    # this assumes we've called
    start, second = cconv.getCallArgs(emu, 2)
    initial = readString(emu, start)
    data = readString(emu, second)
    emu.writeMemory(start + len(initial) + b'\0', data)
    print(initial+data)
    cconv.setReturnValue(emu, dest)
    cconv.deallocateCallSpace(emu, 0)
    return initial+data

def strncat(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    cconv.allocateReturnAddress(emu)    # this assumes we've called
    start, second, max2 = cconv.getCallArgs(emu, 3)
    initial = readString(emu, start)
    data = readString(emu, second)[:max2]
    
    emu.writeMemory(start + len(initial), data)
    print(initial+data)
    cconv.setReturnValue(emu, dest)
    cconv.deallocateCallSpace(emu, 0)
    return initial+data

def strlen(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    cconv.allocateReturnAddress(emu)    # this assumes we've called
    start = cconv.getCallArgs(emu, 1)
    data = readString(emu, start)
    print(len(data))
    cconv.setReturnValue(emu, len(data))
    cconv.deallocateCallSpace(emu, 0)
    return len(data)

def strcmp(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    cconv.allocateReturnAddress(emu)    # this assumes we've called
    start1, start2 = cconv.getCallArgs(emu, 2)
    data1 = readString(emu, start1)
    data2 = readString(emu, start2)
    data1len = len(data1)
    data2len = len(data2)
    failed = False

    if data1len != data2len:
        failed = True
        data1 += '\0'
        data2 += '\0'

    for idx in min(data1len, data2len):
        if data1[idx] != data2[idx]:
            failed = True
            break
    
    retval = data2[idx] - data1[idx]
    if failed:
        print("strcmp failed: %d" % retval)

    cconv.setReturnValue(emu, retval)
    cconv.deallocateCallSpace(emu, 0)
    return retval


PAGE_SIZE = 1 << 12
PAGE_NMASK = PAGE_SIZE - 1
PAGE_MASK = ~PAGE_NMASK
CHUNK_SIZE = 1 << 4
CHUNK_NMASK = CHUNK_SIZE - 1
CHUNK_MASK = ~CHUNK_NMASK

def findNewMemoryMapSpace(emu, size, startingpoint=0x20000000):
    baseva = None
    while not baseva:
        # if we roll into illegal memory, start over at page 2.  skip 0.
        if startingpoint > (1<<(8*emu.psize)):
            startingpoint = 0x1000

        good = True
        for x in range(size):
            mmap = emu.getMemoryMap(startingpoint + x)
            if mmap is None:
                continue

            # we ran into a memory map.  adjust.
            good=False
            startingpoint = mmap[0] + mmap[1]
            startingpoint += PAGE_NMASK
            startingpoint &= PAGE_MASK
            break

        if good:
            baseva = startingpoint

    return baseva


class EmuHeap:
    def __init__(self, emu, size=10*1024, startingpoint=0x20000000):
        self.emu = emu
        self.size = size

        mmap = '\0' * size

        heapbase = self.findNewHeapBase(size, startingpoint)
        if not emu.getMemoryMap(heapbase):
            emu.addMemoryMap(heapbase, 6, 'heap_%x'%heapbase, b'\0'*size)
        self.ptr = heapbase
        self.tracker = {}

    def findNewHeapBase(self, size, startingpoint=0x20000000):
        heapbase = None
        while not heapbase:
            # if we roll into illegal memory, start over at page 2.  skip 0.
            if startingpoint > (1<<(8*self.emu.psize)):
                startingpoint = 0x1000

            good = True
            for x in range(size):
                mmap = self.emu.getMemoryMap(startingpoint + x)
                if mmap is None:
                    continue

                # we ran into a memory map.  adjust.
                good=False
                startingpoint = mmap[0] + mmap[1]
                startingpoint += PAGE_NMASK
                startingpoint &= PAGE_MASK
                break

            if good:
                heapbase = startingpoint
    
        return heapbase

    def malloc(self, size):
        size += CHUNK_NMASK
        size &= CHUNK_MASK
        chunk = self.ptr
        self.ptr += size

        self.tracker[chunk] = size
        return chunk

    def realloc(self, chunk, size):
        if chunk not in self.tracker:
            return 0

        newchunk = self.malloc(size)
        oldsize = self.tracker.get(chunk)
        self.emu.writeMemory(newchunk, self.emu.readMemory(chunk, oldsize))

        return newchunk

    def free(self, addr):
        # really?  nah.  not at this point.
        pass


def getHeap(emu, initial_size=None):
    '''
    Returns a Heap Object.
    If one is not currently created in the emu (stored in emu metadata)
    one is created.  If initial_size is not None, that value is used,
    otherwise the default is used.
    '''
    heap = emu.getMeta('Heap')
    if heap is None:
        if initial_size is not None:
            heap = EmuHeap(emu, initial_size)
        else:
            heap = EmuHeap(emu)
        emu.setMeta('Heap', heap)

    return heap

def HeapAlloc(emu, op=None):
    '''
    This is a functional heap implementation, not intended to behave in any way like 
    the MS heap or any other heap impls available.  It gives you a chunk of memory so
    the program you're playing with keeps going.
    That's it.
    dwflags is ignored completely.
    '''
    ccname, cconv = getLibcCallConv(emu)
    cconv.allocateReturnAddress(emu)    # this assumes we've called
    hheap, dwflags, size = cconv.getCallArgs(emu, 3)

    heap = getHeap(emu)
    allocated_ptr = heap.malloc(size)
    print("malloc(0x%x)  => 0x%x" % (size, allocated_ptr))

    cconv.setReturnValue(emu, allocated_ptr)
    cconv.deallocateCallSpace(emu, 0)

def HeapFree(emu):
    ccname, cconv = getLibcCallConv(emu)
    cconv.allocateReturnAddress(emu)    # this assumes we've called
    hheap, dwflags, va = cconv.getCallArgs(emu, 3)
    print("FREE: 0x%x" % va)
    cconv.setReturnValue(emu, va)
    cconv.deallocateCallSpace(emu, 0)

def malloc(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    cconv.allocateReturnAddress(emu)    # this assumes we've called
    size, = cconv.getCallArgs(emu, 1)

    heap = getHeap(emu)
    allocated_ptr = heap.malloc(size)
    print("malloc(0x%x)  => 0x%x" % (size, allocated_ptr))

    #cconv.setReturnValue(emu, allocated_ptr)
    cconv.setReturnValue(emu, allocated_ptr)
    cconv.deallocateCallSpace(emu, 0)

def free(emu):
    ccname, cconv = getLibcCallConv(emu)
    cconv.allocateReturnAddress(emu)    # this assumes we've called
    va = cconv.getCallArgs(emu, 1)
    print("FREE: 0x%x" % va)
    cconv.setReturnValue(emu, 0)
    cconv.deallocateCallSpace(emu, 0)

def realloc(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    cconv.allocateReturnAddress(emu)    # this assumes we've called
    existptr, size, = cconv.getCallArgs(emu, 2)

    heap = getHeap(emu)
    allocated_ptr = heap.realloc(existptr, size)

    cconv.setReturnValue(emu, allocated_ptr)
    cconv.deallocateCallSpace(emu, 0)

def HeapReAlloc(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    cconv.allocateReturnAddress(emu)    # this assumes we've called
    hheap, dwflags, existptr, size, = cconv.getCallArgs(emu, 4)

    heap = getHeap(emu)
    allocated_ptr = heap.realloc(existptr, size)

    cconv.setReturnValue(emu, allocated_ptr)
    cconv.deallocateCallSpace(emu, 0)

def skip(emu, op):
    emu.setProgramCounter(emu.getProgramCounter()+len(op))

def ret0(emu, op):
    ccname, cconv = getLibcCallConv(emu)
    cconv.setReturnValue(emu, 0)

def ret1(emu, op):
    ccname, cconv = getLibcCallConv(emu)
    cconv.setReturnValue(emu, 1)

def retneg1(emu, op):
    ccname, cconv = getLibcCallConv(emu)
    cconv.setReturnValue(emu, -1)


def syslog(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    cconv.allocateReturnAddress(emu)    # this assumes we've called

    loglvl, strlength = cconv.getCallArgs(emu, 2)
    string = readString(emu, strlength)
    count = string.count('%')
    neg2 = string.count('%%')
    count -= (2*neg2)

    args = cconv.getCallArgs(emu, count+2)[2:]
    outstring = string % args
    print("SYSLOG(%d): %s" % (loglvl, outstring))
    for s in args:
        if emu.isValidPointer(s):
            print("\t" + readString(emu, s))
    cconv.setReturnValue(emu, 0)
    cconv.deallocateCallSpace(emu, 0)

def nop(emu, op=None):
    pass

import_map = {
        '*.syslog': syslog,
        '*.malloc': malloc,
        '*.free': free,
        '*.realloc': realloc,
        '*.strlen': strlen,
        '*.strcmp': strcmp,
        '*.strcat': strcat,
        '*.strcpy': strcpy,
        '*.strncpy': strncpy,
        '*.memcpy': memcpy,
        '*.memset': memset,
        'kernel32.HeapAlloc': HeapAlloc,
        'kernel32.HeapFree': HeapFree,
        'kernel32.HeapReAlloc': HeapReAlloc,
        'kernel32.HeapDestroy': nop,
        'kernel32.HeapCreate': nop,     # malloc takes care of this
        }

class TestEmulator:
    def __init__(self, emu, vw=None, verbose=False, fakePEB=False, guiFuncGraphName=None):
        self.vw = None
        self.vwg = None

        self.emu = emu

        if vw is not None:
            self.vw = vw
            self.vwg = self.vw.getVivGui()
        elif hasattr(emu, 'vw'):
            self.vw = emu.vw
            self.vwg = self.vw.getVivGui()

        self.verbose = verbose
        self.guiFuncGraphName = guiFuncGraphName

        self.XWsnapshot = {}
        self.cached_mem_locs = []
        self.call_handlers = {}
        self.hookImports()

        self.teb = None
        self.peb = None
        if fakePEB:
            self.initFakePEB()

    def initFakePEB(self):
        peb = findNewMemoryMapSpace(self.emu, PEBSZ, 0x7ffd3000)
        self.emu.addMemoryMap(peb, 6, 'FakePEB', b'\0'*PEBSZ)
        teb = findNewMemoryMapSpace(self.emu, TEBSZ, 0x7ffdc000)
        self.emu.addMemoryMap(teb, 6, 'FakeTEB', b'\0'*TEBSZ)

        self.emu.writeMemoryPtr(teb+0x30, peb)
        # fake TEB: c4eea6060000a70600e0a60600000000001e0000000000000040fd7f00000000401700000c140000000000002c40fd7f00c0fd7f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000090400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

        # fake PEB: 00000108ffffffff0000e7008088d277b817400000000000000040008083d27700000000000000000100000038d5dc7700000000000000000000eb77000000006082d277ffffffff0700000000006f7f0000000090056f7f0000fb7f2402fc7f4806fd7f01000000000000000000000000809b076de8ffff000010000020000000000100001000000c000000100000000085d27700005d0000000000140000004083d2770600000001000000b11d00010200000003000000060000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

        if self.emu.psize == 4:
            self.emu.setSegmentInfo(e_i386.SEG_FS, teb, TEBSZ)
        else:
            self.emu.setSegmentInfo(e_amd64.SEG_GS, teb, TEBSZ)


    def hookImports(self):
        if not hasattr(self.emu, 'vw') or self.emu.vw is None:
            return

        for impva, impsz, imptype, impname in self.emu.vw.getImports():
            if impname in import_map:
                self.call_handlers[impva] = import_map.get(impname)

    def printMemStatus(self, op=None, use_cached=False):
        emu = self.emu
        pc = emu.getProgramCounter()
        SP = emu.getStackCounter()
        if op is None:
            return

        done = []
        if use_cached:
            addrs = self.cached_mem_locs
        else:
            addrs = []
            for oper in op.opers:
                try:
                    # value
                    addr = oper.getOperValue(op, emu)
                    if type(addr) == int:
                        if addr not in addrs:
                            addrs.append(addr)
                    # address
                    if oper.isDeref():
                        addr = oper.getOperAddr(op, emu)
                        if addr is not None:
                            if addr not in addrs:
                                addrs.append(addr)

                except Exception as e:
                    print("error: %s" % e)

        for addr in addrs:
            if not emu.isValidPointer(addr):
                #if emu.vw.verbose:
                #    if type(addr) == int:
                #        print("No valid memory at address: 0x%x" % addr)
                #    else:
                #        print("No valid memory at address: %s" % addr)
                continue

            print(self.XW(addr, snapshot=SNAP_SWAP))
        self.cached_mem_locs = addrs


    def XW(self, address, length = 32, dwperline = 8, snapshot=0):
        output = []
        mm = self.emu.getMemoryMap(address)
        if mm is None:
            return ''

        mmva, mmsz, mmperm, mmname = mm
        if mmva+mmsz < address + (length*4):
            goodbcnt = (mmva+mmsz-address)
            diff = (length*4) - goodbcnt
            bs = self.emu.readMemory(address, goodbcnt)
            bs += b'A' * diff

        else:
            bs = self.emu.readMemory(address, length*4)

        for i in range(length):
            addr = address + (i * 4)
            if (i % dwperline == 0):
                output.append("%.08x:\t "%(addr))

            data = bs[i*4:(i*4)+4]

            # do the snapshotting thing
            pre = post = ''
            if snapshot in (SNAP_DIFF, SNAP_SWAP):
                sdata = self.XWsnapshot.get(addr) 
                if sdata is not None and sdata != data:
                    # highlight the text somehow
                    pre = '\x1b[7m'
                    post = '\x1b[27m'

            if snapshot in (SNAP_CAP, SNAP_SWAP):
                self.XWsnapshot[addr] = data
            output.append(pre + data.hex() + post)

            if ((i+1) % dwperline == 0):
                output.append("\n")
            else:
                output.append("  ")

        return "".join(output)


    def showPriRegisters(self, snapshot=SNAP_NORM):
        emu = self.emu
        print("\nRegisters:")
        reggrps = emu.vw.arch.archGetRegisterGroups()
        for name, gen_regs in reggrps:
            if name == 'general':
                break

        reg_table, meta_regs, PC_idx, SP_idx, reg_vals = emu.getRegisterInfo()
        reg_dict = { reg_table[i][0] : (reg_table[i][1], reg_vals[i]) for i in range(len(reg_table)) }

        # print(through the various registers)
        for i in range(len(gen_regs)):
            rname = gen_regs[i]
            rsz, rval = reg_dict.get(rname)

            # line break every so often
            if (i%5 == 0):
                sys.stdout.write("\n")#%4x"%i)

            # do snapshotting:
            pre = post = ''
            if snapshot in (SNAP_DIFF, SNAP_SWAP):
                srval = self.XWsnapshot.get(rname) 
                if srval is not None and srval != rval:
                    # highlight the text somehow
                    pre = '\x1b[7m'
                    post = '\x1b[27m'

            if snapshot in (SNAP_CAP, SNAP_SWAP):
                self.XWsnapshot[rname] = rval

            rnpad = ' ' * (11 - len(rname))

            fmt = "%%s%%s: %%%dx%%s" % (rsz//4)
            sys.stdout.write(fmt % (rnpad, pre + rname, rval, post))

        # Line feed
        print("\n")

    def showFlags(self):
        """
        Show the contents of the Status Register
        """
        #print("\tStatus Flags: \tRegister: %s\n" % (bin(self.getStatusRegister())))
        try:
            print("\tStatFlags: " + '\t'.join(["%s %s" % (f,v) for f,v in self.emu.getStatusFlags().items()]))
        except Exception as e:
            print("no flags: ", e)


    def stackDump(self):
        emu = self.emu
        print("Stack Dump:")
        sp = emu.getStackCounter()
        for x in range(16):
            print("\t0x%x:\t0x%x" % (sp, emu.readMemValue(sp, emu.psize)))
            sp += emu.psize


    def printStats(self, i):
        curtime = time.time()
        dtime = curtime - self.startRun
        print("since start: %d instructions in %.3f secs: %3f ops/sec" % \
                (i, dtime, i//dtime))

    def runStep(self, maxstep=1000000, follow=True, showafter=True, runTil=None, pause=True, silent=False, finish=0, tracedict=None):
        '''
        runStep is the core "debugging" functionality for this emulation-helper.  it's goal is to 
        provide a single-step interface somewhat like what you might get from a GDB experience.  

        pertinent registers are printed with their values, the current instruction, and any helpers
        that the operands may point to in memory (as appropriate).

        special features:
        * tracedict allows code to be evaluated and printed at specific addresses: 
                tracedict={va:'python code here', 'locals':{'something':4}}

        * prints out the operands *after* exection as well  (arg:showafter=True) 

        * cli interface allows viewing and modifying memory/python objects:
                rax
                [rax]
                [rax:23]
                [rax+8:4]
                [0xf00b4:8]
                rax=42
                [0xf00b4]=0x47145
        * cli allows skipping printing  (arg:silent=True)
                silent=True
        * cli allows running until a VA without pauses: 
                go 0x12345
        * cli allows executing until next branch:
                b
        * cli allows dumping the stack:
                stack
        * cli allows viewing/setting the Program Counter:
                pc
                pc=0x43243
        * cli allows skipping instructions:
                skip
        * cli allows numerous libc-style functions:
                memset
                memcpy
                strcpy
                strncpy
                strcat
                strlen
        
        * call_handlers dict (global in the library) allows swapping in our python code in place of 
            calls to other binary code, like memcpy, or other code which may fail in an emulator

        '''
        emu = self.emu

        mcanv = e_memcanvas.StringMemoryCanvas(emu, syms=emu.vw)
        self.mcanv = mcanv  # store it for later inspection

        # set up tracedict
        if tracedict is None:
            tracedict = {}
        else:
            print("tracedict entries for %r" % (','.join([hex(key) for key in tracedict.keys() if type(key) == int])))


        nonstop = 0
        tova = None
        quit = False
        moveon = False
        emuBranch = False
        silentUntil = None

        # set silentExcept to include all tracedict items
        silentExcept = [va for va, expr in tracedict.items() if expr is None]

        i = 0
        self.startRun = time.time()
        while maxstep > i:
            try:
                skip = skipop = False
                i += 1

                pc = emu.getProgramCounter()
                if pc in (runTil, finish):
                    print("PC reached 0x%x." % pc)
                    break

                op = emu.parseOpcode(pc)
                self.op = op    # store it for later in case of post-mortem

                # cancel emuBranch as we've come to one
                if op.isReturn() or op.isCall():
                    emuBranch = False

                #### TRACING 
                for key in (pc, 'ALL'):
                    tdata = tracedict.get(key)
                    if tdata is not None:
                        try:
                            lcls = locals()
                            outlcls = tracedict.get('locals')
                            if outlcls is not None:
                                lcls.update(outlcls)

                            lcls.update(emu.getRegisters())
                            if isinstance(emu, vtrace.Trace):
                                lcls.update(emu.getRegisterContext().getRegisters())

                            print(repr(eval(tdata, globals(), lcls)))
                        except Exception as e:
                            print("TraceMonitor ERROR at 0x%x: %r" % (pc, e))

                ####

                if silentUntil == pc:
                    silent = False
                    silentUntil = None
                    self.printStats(i)

                if silent and not pc in silentExcept:
                    showafter = False
                else:
                    # do all the interface stuff here:
                    self.showPriRegisters(snapshot=SNAP_SWAP)
                    self.showFlags() # ARM fails this right now.
                    try:
                        self.printMemStatus(op)
                    except Exception as e:
                        print("MEM ERROR: %s:    0x%x %s" % (e, op.va, op))
                        import traceback
                        traceback.print_exc()

                    print("Step: %s" % i)
                    mcanv.clearCanvas()
                    try:
                        op.render(mcanv)
                    except Exception as e:
                        print("ERROR rendering opcode: %r" % e)

                    extra = self.getNameRefs(op)

                    opbytes = emu.readMemory(pc,len(op))
                    print("%.4x\t%20s\t%s\t%s"%(pc,hexlify(opbytes),mcanv.strval, extra))

                    print("---------")
                    prompt = "q<enter> - exit, eval code to execute, 'skip' an instruction, 'b'ranch, 'go [+]#' to va or +# instrs or enter to continue: "

                    # nonstop controls whether we stop.  tova indicates we're hunting for a va, otherwise 
                    # treat nonstop as a negative-counter
                    if tova is not None:
                        if pc == tova:
                            nonstop = 0

                    elif nonstop:
                        nonstop -= 1

                    if not (emuBranch or nonstop) and pause:
                        tova = None
                        nextva = op.va + len(op)
                        moveon = False

                        # send the selected GUI window to current program counter
                        if self.guiFuncGraphName is not None and not silent:
                            if self.vwg is not None:
                                self.vwg.sendFuncGraphTo(pc)
                            else:
                                print("can't send FuncGraph to 0x%x because we don't have a handle to the Viv GUI" % pc)

                        # UI Interface!  interact with the user
                        uinp = input(prompt)
                        while len(uinp) and not (moveon or quit or emuBranch):
                            try:
                                if uinp == "q":
                                    quit = True
                                    break

                                elif uinp.startswith('silent'):
                                    parts = uinp.split(' ')
                                    silentUntil = parseExpression(emu, parts[-1], {'next':nextva})
                                    print("silent until 0x%x" % silentUntil)
                                    silent = True

                                elif uinp.startswith('go '):
                                    args = uinp.split(' ')

                                    if args[-1].startswith('+'):
                                        nonstop = parseExpression(emu, args[-1], {'next': nextva})
                                    else:
                                        tova = parseExpression(emu, args[-1], {'next': nextva})
                                        nonstop = 1
                                    break

                                elif uinp in ('b', 'branch'):
                                    emuBranch = True
                                    break

                                elif uinp == 'stack':
                                    self.stackDump()
                                    moveon = True
                                    break

                                elif uinp == 'refresh':
                                    # basically does a NOP, doesn't change anything, just let the data be reprinted.
                                    moveon = True
                                    break

                                elif uinp.startswith('pc=') or uinp.startswith('pc ='):
                                    print("handling setProgramCounter()")
                                    args = uinp.split('=')
                                    newpc = parseExpression(emu, args[-1])
                                    print("new PC: 0x%x" % newpc)
                                    emu.setProgramCounter(newpc)
                                    moveon = True
                                    break

                                elif '=' in uinp:
                                    print("handling generic register/memory writes")
                                    args = uinp.split('=')
                                    data = args[-1].strip() #   .split(',')  ??? why did i ever do this?

                                    if '[' in args[0]:
                                        # memory derefs
                                        tgt = args[0].replace('[','').replace(']','').split(':')
                                        if len(tgt) > 1:
                                            size = parseExpression(emu, tgt[-1])
                                        else:
                                            size = 4

                                        addrstr = tgt[0]
                                        memaddr = parseExpression(emu, addrstr)

                                        if data.startswith('"') and data.endswith('"'):
                                            # write string data
                                            emu.writeMemory(memaddr, data[1:-1])
                                        else:
                                            # write number
                                            emu.writeMemValue(memaddr, parseExpression(emu, data), size)

                                    else:
                                        # must be registers
                                        emu.setRegisterByName(args[0], parseExpression(emu, data))

                                elif uinp.strip().startswith('[') and ']' in uinp:
                                    try:
                                        idx = uinp.find('[') + 1
                                        eidx = uinp.find(']', idx)
                                        expr = uinp[idx:eidx]
                                        print("handling memory read at [%s]" % expr)
                                        size = emu.getPointerSize()
                                        if ':' in expr:
                                            nexpr, size = expr.rsplit(':',1)
                                            try:
                                                size = parseExpression(emu, size)
                                                expr = nexpr
                                            except Exception as e:
                                                # if number fails, just continue with a default size and the original expr
                                                print("unknown size: %r.  using default size." % size)

                                        va = parseExpression(emu, expr)
                                        data = emu.readMemory(va, size)
                                        print("[%s:%s] == %r" % (expr, size, data.hex()))
                                    except Exception as e:
                                        print("ERROR: %r" % e)

                                elif uinp == 'skip':
                                    newpc = emu.getProgramCounter() + len(op)
                                    print("new PC: 0x%x" % newpc)
                                    skipop = True
                                    break

                                elif uinp == 'memset':
                                    print(memset(emu))
                                    skipop = True
                                elif uinp == 'memcpy':
                                    print(memcpy(emu))
                                    skipop = True
                                elif uinp == 'strcpy':
                                    print(strcpy(emu))
                                    skipop = True
                                elif uinp == 'strncpy':
                                    print(strncpy(emu))
                                    skipop = True
                                elif uinp == 'strcat':
                                    print(strcat(emu))
                                    skipop = True
                                elif uinp == 'strlen':
                                    print(strlen(emu))
                                    skipop = True

                                elif uinp == 'malloc':
                                    print(malloc(emu))
                                    skipop = True
                                else:
                                    try:
                                        lcls = {'next': nextva}
                                        lcls.update(locals())
                                        lcls.update(emu.getRegisters())
                                        out = eval(uinp, globals(), lcls)

                                        taint = emu.getVivTaint(out)
                                        if taint:
                                            out = "taint: %s: %s" % (taint[1], emu.reprVivTaint(taint))
                                        
                                        if type(out) == int:
                                            print(hex(out))
                                        else:
                                            print(out)
                                    except:
                                        import sys
                                        sys.excepthook(*sys.exc_info())

                            except:
                                import traceback
                                traceback.print_exc()

                            #self.printStats(i)
                            uinp = input(prompt)

                if quit:
                    print("Quitting!")
                    self.printStats(i)
                    return

                if moveon:
                    continue

                # handle Calls separately
                if op.isCall() and not skipop:
                    self.dbgprint("Call...")
                    handler = None
                    for brva, brflags in op.getBranches(emu=emu):
                        if brflags & envi.BR_FALL:
                            continue

                        self.dbgprint("brva: 0x%x  brflags: 0x%x" % (brva, brflags))
                        handler = self.call_handlers.get(brva)
                        if handler is not None:
                            break

                    self.dbgprint( " handler for call to (0x%x): %r" % (brva, handler))
                    if handler is not None:
                        handler(emu, op)
                        skipop = True

                    elif follow and not skip and not skipop:
                        # use the emulator to execute the call
                        starteip = emu.getProgramCounter()
                        if hasattr(emu, 'emumon') and emu.emumon is not None:
                            emu.emumon.prehook(emu, op, starteip)

                        emu.executeOpcode(op)
                        endeip = emu.getProgramCounter()
                        i += 1
                        if hasattr(emu, 'emumon') and emu.emumon is not None:
                            emu.emumon.posthook(emu, op, endeip)

                        self.dbgprint("starteip: 0x%x, endeip: 0x%x  -> %s" % (starteip, endeip, emu.vw.getName(endeip)))
                        if hasattr(emu, 'curpath'):
                            vg_path.getNodeProp(emu.curpath, 'valist').append(starteip)
                        skip = True

                # if not already emulated a call, execute the instruction here...
                if not skip and not skipop:
                    emu.stepi()

                    # print the updated latest stuff....
                    if showafter:
                        try:
                            extra = self.getNameRefs(op)
                            if len(extra):
                                print("after:\t%s\t%s"%(mcanv.strval, extra))

                            self.printMemStatus(op, use_cached=True)
                        except Exception as e:
                            print("MEM ERROR: %s:    0x%x %s" % (e, op.va, op))
                            import sys
                            sys.excepthook(*sys.exc_info())

                # unless we've asked to skip the instruction...
                elif skipop:
                    newpc = emu.getProgramCounter() + len(op)
                    emu.setProgramCounter(newpc)

            except KeyboardInterrupt:
                self.printStats(i)
                break

            except envi.SegmentationViolation:
                import sys
                sys.excepthook(*sys.exc_info())
                break

            except:
                import sys
                sys.excepthook(*sys.exc_info())

        self.printStats(i)


    def dbgprint(self, *args, **kwargs):
        if self.verbose:
            data = '\t'.join(args)
            print(data)

    def getNameRefs(self, op):
        emu = self.emu
        extra = ''
        ###  HACK: NOT FOR PUBLIC CONSUMPTION:
        #taintPause = emu._pause_on_taint
        #emu._pause_on_taint = False
        try:

            for operidx, oper in enumerate(op.opers):
                opval = oper.getOperValue(op, emu)
                if type(opval) == int:
                    opnm = emu.vw.getName(opval)
                    if opnm is None and hasattr(emu, 'getVivTaint'):
                        taint = emu.getVivTaint(opval)
                        if taint:
                            taintrepr = emu.reprVivTaint(taint)
                            opnm = "%s (%s)" % (taint[1], taintrepr)

                    if opnm is not None:
                        extra += '\t; $%d = %r' % (operidx, opnm)

                if oper.isDeref():
                    dopval = oper.getOperAddr(op, emu)
                    if type(dopval) == int:
                        dopnm = emu.vw.getName(dopval)
                        if opnm is None and hasattr(emu, 'getVivTaint'):
                            taint = emu.getVivTaint(opval)
                            if taint:
                                taintrepr = emu.reprVivTaint(taint)
                                opnm = "%s (%s)" % (taint[1], taintrepr)

                        if dopnm is not None:
                            extra += '\t; &$%d = %r' % (operidx, dopnm)

        except Exception as e:
            print("getNameRefs: ERROR: %r" % e)
        #finally:
        #    emu._pause_on_taint = taintPause
        return extra

    def runUntil(self, eip=0, mnem=None, maxstep=1000000):
        emu = self.emu
        for i in range(maxstep):
            pc = emu.getProgramCounter()
            op = emu.parseOpcode(pc)
            opbytes = emu.readMemory(pc,len(op))
            if pc == eip or op.mnem == mnem:
                break
            emu.stepi()
        runStep(emu)

    def printWriteLog(self):
        print('\n'.join(['0x%.8x: 0x%.8x << %32r %r' % (x,y,d.hex(),d) for x,y,d in self.emu.path[2].get('writelog')]))


    def insertReadWriteComments(self, vw):
        for va, tva, data in self.emu.path[2].get('readlog'):
            insertComment(vw, va, "[r:%x] %r (%r)" % (tva, data.hex(), data))

        for va, tva, data in self.emu.path[2].get('writelog'):
            insertComment(vw, va, "[W:%x] %r (%r)" % (tva, data.hex(), data))


import vivisect.impemu.monitor as vi_mon
import vivisect.symboliks.analysis as vs_anal

class SymbolikTraceAnalMod(vi_mon.AnalysisMonitor):
    def __init__(self, emu):
        self.emu = emu
        self.sctx = vs_anal.getSymbolikAnalysContext(emu.vw)
        self.xlate = self.sctx.getTranslator()

    def prehook(self, emu, op, starteip):
        self.xlate.translateOp(op)

def insertComment(vw, va, comment):
    curcmt = vw.getComment(va)
    if curcmt is not None:
        vw.setComment(va, "%s  ; %s" % (comment, curcmt))
    else:
        vw.setComment(va, comment)



if __name__ == "__main__":
    main(sys.argv)


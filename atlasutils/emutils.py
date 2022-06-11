#!/usr/bin/env python
import os
import cmd
import sys
import time
import psutil
import struct
import struct
import vtrace
import traceback
import collections

import envi
import envi.exc as e_exc
import envi.memory as e_m
import envi.expression as e_expr
import envi.memcanvas as e_memcanvas

import envi.archs.i386 as e_i386
import envi.archs.amd64 as e_amd64

import vivisect
import vivisect.cli as viv_cli
import visgraph.pathcore as vg_path
from binascii import hexlify, unhexlify

from atlasutils.errno import *
from envi.expression import ExpressionFail

from envi.const import MM_READ, MM_WRITE, MM_EXEC

SNAP_NORM = 0
SNAP_CAP = 1
SNAP_DIFF = 2
SNAP_SWAP = 3

PEBSZ = 4096
TEBSZ = 4096
TLSSZ = 4096

def parseExpression(emu, expr, lcls={}):
    '''
    localized updated expression parser for the emulator at any state
    '''
    if hasattr(emu, 'vw'):
        lcls.update(emu.vw.getExpressionLocals())
    lcls.update(emu.getRegisters())
    if isinstance(emu, vtrace.Trace):
        lcls.update(emu.getRegisterContext().getRegisters())
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
def runStep(emu, maxstep=1000000, follow=True, showafter=True, runTil=None, pause=True, silent=False, finish=0, tracedict=None, verbose=False, guiFuncGraphName=None, bps=()):
    global testemu

    if testemu is None or testemu.emu != emu:
        testemu = TestEmulator(emu, verbose=verbose, guiFuncGraphName=guiFuncGraphName)
        testemu.call_handlers.update(call_handlers)
    
    testemu.runStep(maxstep=maxstep, follow=follow, showafter=showafter, runTil=runTil, pause=pause, silent=silent, finish=finish, tracedict=tracedict, bps=bps)


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


# our hacky HEAP implementation (good for RE, not for heap-exploitation context)
PAGE_SIZE = 1 << 12
PAGE_NMASK = PAGE_SIZE - 1
PAGE_MASK = ~PAGE_NMASK
CHUNK_SIZE = 1 << 4
CHUNK_NMASK = CHUNK_SIZE - 1
CHUNK_MASK = ~CHUNK_NMASK


class EmuHeap:
    def __init__(self, emu, size=10*1024, startingpoint=0x20000000):
        self.emu = emu
        self.size = size

        mmap = '\0' * size

        #heapbase = emu.findFreeMemoryBlock(size, startingpoint)
        #if not emu.getMemoryMap(heapbase):
        #    emu.addMemoryMap(heapbase, 6, 'heap_%x'%heapbase, b'\0'*size)
        heapbase = emu.allocateMemory(size, 6, startingpoint, 'heap')    
        self.ptr = heapbase
        self.tracker = {}
        self.freed = {}

    def malloc(self, size):
        size += CHUNK_NMASK
        size &= CHUNK_MASK
        chunk = self.ptr
        self.ptr += size

        self.tracker[chunk] = (size, self.emu.getProgramCounter())
        return chunk

    def realloc(self, chunk, size):
        if chunk not in self.tracker:
            return 0

        newchunk = self.malloc(size)
        # FIXME: error here if not found....
        oldsize, oldaccess = self.tracker.get(chunk)

        print("realloc: old: 0x%x  new: 0x%x      oldsize: 0x%x   newsize: 0x%x" % (chunk, newchunk, oldsize, size))
        self.emu.writeMemory(newchunk, self.emu.readMemory(chunk, oldsize))

        return newchunk

    def free(self, addr):
        self.freed[addr] = self.emu.getProgramCounter()

    def dump(self):
        out = []
        for baseva, (size, allocpc) in list(self.tracker.items()):
            data = self.emu.readMemory(baseva, size)
            out.append("[0x%x:0x%x]: %r (0x%x)" % (baseva, size, data.hex(), allocpc))

        return '\n'.join(out)


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


#######  replacement functions.  can set these in TestEmulator().call_handlers 
#######  to execute these in python instead of the supporting library
#######  can also be run from runStep() ui to execute the replacement function
STRUNCATE = 80


#### Calling Convention helpers:
def getMSCallConv(emu, tva=None, wintel32pref='stdcall'):
    if hasattr(emu, 'vw') and emu.vw is not None:
        ccname = None
        tloc = emu.vw.getLocation(tva)
        if tloc is not None:
            tlva, tlsz, tltype, tltinfo = tloc
            if tltype == vivisect.LOC_IMPORT:
                impapi = emu.vw.getImpApi(tltinfo)
                if impapi is not None:
                    rettyp, _, ccname, realname, args = impapi

        if ccname is None:
            if emu.psize == 4: # and emu._arch ????:
                ccname = wintel32pref
            else:
                ccname = emu.vw.getMeta('DefaultCall')

        cconv = emu.getCallingConvention(ccname)
        return ccname, cconv

    return emu.getCallingConventions()[0]

def getLibcCallConv(emu):
    if hasattr(emu, 'vw') and emu.vw is not None:
        ccname = emu.vw.getMeta('DefaultCall')
        cconv = emu.getCallingConvention(ccname)
        return ccname, cconv

    return emu.getCallingConventions()[0]


#### posix function helpers
def malloc(emu, op=None):
    '''
    emulator hook for malloc calls
    '''
    ccname, cconv = getLibcCallConv(emu)
    size, = cconv.getCallArgs(emu, 1)

    heap = getHeap(emu)
    allocated_ptr = heap.malloc(size)
    print("malloc(0x%x)  => 0x%x" % (size, allocated_ptr))

    cconv.execCallReturn(emu, allocated_ptr, 0)

def calloc(emu, op=None):
    '''
    emulator hook for malloc calls
    '''
    ccname, cconv = getLibcCallConv(emu)
    elements, size = cconv.getCallArgs(emu, 2)

    heap = getHeap(emu)
    allocated_ptr = heap.malloc(size * elements)
    print("calloc(0x%x, 0x%x)  => 0x%x" % (elements, size, allocated_ptr))

    cconv.execCallReturn(emu, allocated_ptr, 0)

def free(emu, op=None):
    '''
    emulator hook for free calls
    '''
    ccname, cconv = getLibcCallConv(emu)
    va, = cconv.getCallArgs(emu, 1)
    heap = getHeap(emu)
    heap.free(va)
    print("FREE: 0x%x" % va)
    cconv.execCallReturn(emu, 0, 0)

def realloc(emu, op=None):
    '''
    emulator hook for realloc calls
    '''
    ccname, cconv = getLibcCallConv(emu)
    existptr, size = cconv.getCallArgs(emu, 2)

    heap = getHeap(emu)
    allocated_ptr = heap.realloc(existptr, size)
    cconv.execCallReturn(emu, allocated_ptr, 0)

def ret0(emu, op):
    '''
    emulator hook to just return 0
    '''
    ccname, cconv = getLibcCallConv(emu)
    cconv.execCallReturn(emu, 0, 0)

def ret1(emu, op):
    '''
    emulator hook to just return 1
    '''
    ccname, cconv = getLibcCallConv(emu)
    cconv.execCallReturn(emu, 1, 0)

def retneg1(emu, op):
    '''
    emulator hook to just return -1
    '''
    ccname, cconv = getLibcCallConv(emu)
    cconv.execCallReturn(emu, -1, 0)


def syslog(emu, op=None):
    '''
    emulator hook for calls to syslog
    '''
    ccname, cconv = getLibcCallConv(emu)
    loglvl, strlength = cconv.getCallArgs(emu, 2)
    string = readString(emu, strlength)
    count = string.count(b'%')
    neg2 = string.count(b'%%')
    count -= (2*neg2)

    args = cconv.getCallArgs(emu, count+2)[2:]
    outstring = string % args
    print("SYSLOG(%d): %s" % (loglvl, outstring))
    for s in args:
        if emu.isValidPointer(s):
            print("\t" + readString(emu, s))
    cconv.execCallReturn(emu, 0, 0)

def nop(emu, op=None):
    pass

def memset(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    dest, char, count = cconv.getCallArgs(emu, 3)

    data = (b'%c' % char) * count
    emu.writeMemory(dest, data)
    print(data)
    cconv.execCallReturn(emu, 0, 0)
    return data

def memcpy(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    dest, src, length = cconv.getCallArgs(emu, 3)
    data = emu.readMemory(src, length)
    emu.writeMemory(dest, data)
    print(data)
    cconv.execCallReturn(emu, dest, 0)

    return data

def memcpy_s(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    dest, destlen, src, length = cconv.getCallArgs(emu, 4)
    data = emu.readMemory(src, length)
    emu.writeMemory(dest, data)
    print(data)
    cconv.execCallReturn(emu, dest, 0)

    return data

def strncpy(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    dest, src, length = cconv.getCallArgs(emu, 3)
    data = emu.readMemory(src, length)
    nulloc = data.find(b'\0')
    if nulloc != -1:
        data = data[:nulloc]
    emu.writeMemory(dest, data)
    print(data)
    cconv.execCallReturn(emu, dest, 0)
    return data

def strncpy_s(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    dest, destsz, src, lenarg = cconv.getCallArgs(emu, 4)
    
    length = min(destsz, lenarg)
    data = emu.readMemory(src, length)

    nulloc = data.find(b'\0')
    if nulloc != -1:
        data = data[:nulloc]

    data += b'\0'

    # check to see if need to return an error??
    retval = 0
    if lenarg > length + 1:
        retval = STRUNCATE

    emu.writeMemory(dest, data)
    print("strncpy_s(0x%x, %r)" % (dest, data))
    cconv.execCallReturn(emu, retval, 0)
    return data

def strcpy(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    dest, src = cconv.getCallArgs(emu, 2)
    data = readString(emu, src) + b'\0'
    emu.writeMemory(dest, data)
    print("strncpy(0x%x, %r)" % (dest, data))
    cconv.execCallReturn(emu, dest, 0)
    return data

def strcat(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    start, second = cconv.getCallArgs(emu, 2)
    initial = readString(emu, start)
    data = readString(emu, second)
    emu.writeMemory(start + len(initial) + b'\0', data)
    print("strcat(0x%x, 0x%x)  => %r + %r" % (start, second, initial, data))
    cconv.execCallReturn(emu, dest, 0)
    return initial+data

def strncat(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    start, second, max2 = cconv.getCallArgs(emu, 3)
    initial = readString(emu, start)
    data = readString(emu, second)[:max2]
    
    emu.writeMemory(start + len(initial), data)
    print("strncat(0x%x, 0x%x, 0x%x)  => %r + %r" % (start, second, max2, initial, data))
    cconv.execCallReturn(emu, dest, 0)
    return initial+data

def strncat_s(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    start, destsz, second, max2 = cconv.getCallArgs(emu, 4)
    initial = readString(emu, start)
    data = readString(emu, second)[:max2]

    initiallen = len(initial)
    writelen = destsz - initiallen
    
    emu.writeMemory(start + initiallen, data[:writelen])
    print("strncat(0x%x, 0x%x, 0x%x, 0x%x)  => %r + %r" % (start, destsz, second, max2, initial, data))
    cconv.execCallReturn(emu, 0, 0)
    return initial+data

def strtok_s(emu, op=None):
    print("strtok_s()")
    ccname, cconv = getLibcCallConv(emu)
    strToken, strDelimit, pCtx = cconv.getCallArgs(emu, 3)
    print("strtok_s(0x%x, 0x%x, 0x%x)" % (strToken, strDelimit, pCtx))

    if strToken:
        # this is the first calling for this string
        start = strToken

    else:
        # this is a follow-on calling for this string
        start = emu.readMemoryPtr(pCtx)

    # do the normal stuff
    initial = readString(emu, start)
    initiallen = len(initial)

    delims = readString(emu, strDelimit)
    
    off = 0
    found = False
    while off < initiallen:
        # is mybyte in delims
        mybyte = initial[off]
        off += 1

        if mybyte in delims:
            found = True
            break

    if found:
        emu.writeMemory(start + off-1, b'\0')

    if initiallen:
        emu.writeMemoryPtr(pCtx, start+off)
        retval = start
        print("strtok_s() %r  (%r) => %r" % (initial, delims, initial[:off]))

    else:
        retval = 0
        print("strtok_s() -> end")

    cconv.execCallReturn(emu, retval, 0)
    return retval

def strrchr(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    cstr, char = cconv.getCallArgs(emu, 2)
    initial = readString(emu, cstr)
    idx = initial.rfind(char)
    if idx == -1:
        retval = 0
    else:
        retval = cstr + idx
    
    print("strrchr(%r, %r)" % (initial, char))
    cconv.execCallReturn(emu, retval, 0)
    return retval

def strlen(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    start, = cconv.getCallArgs(emu, 1)
    data = readString(emu, start)
    print("strlen(%r) => 0x%x" % (data, len(data)))
    cconv.execCallReturn(emu, len(data), 0)
    return len(data)

def strcmp(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    start1, start2 = cconv.getCallArgs(emu, 2)
    data1 = readString(emu, start1)
    data2 = readString(emu, start2)
    print("strcmp(%r, %r)" % (data1, data2))
    data1len = len(data1)
    data2len = len(data2)
    failed = False

    if data1len != data2len:
        failed = True
        data1 += b'\0'
        data2 += b'\0'

    for idx in range(min(data1len, data2len)):
        if data1[idx] != data2[idx]:
            failed = True
            break
    
    retval = data2[idx] - data1[idx]
    if failed:
        print("strcmp failed: %d" % retval)

    cconv.execCallReturn(emu, retval, 0)
    return retval

def strncmp(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    start1, start2, count = cconv.getCallArgs(emu, 3)
    data1 = readString(emu, start1)[:count]
    data2 = readString(emu, start2)[:count]
    print("strncmp(%r, %r, %r)" % (data1, data2, count))
    data1len = len(data1)
    data2len = len(data2)
    failed = False

    if data1len != data2len:
        failed = True
        data1 += b'\0'
        data2 += b'\0'

    for idx in range(min(data1len, data2len)):
        if data1[idx] != data2[idx]:
            failed = True
            break
    
    retval = data2[idx] - data1[idx]
    if failed:
        print("strncmp failed: %d" % retval)

    cconv.execCallReturn(emu, retval, 0)
    return retval

def strdup(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    strSource, = cconv.getCallArgs(emu, 1)

    string = emu.readMemString(strSource) + b'\0'
    print("strdup(%r)" % (string))

    heap = getHeap(emu)
    dupe = heap.malloc(len(string))
    emu.writeMemory(dupe, string)

    cconv.execCallReturn(emu, dupe, 1)


#### Win32 helper functions
def Sleep(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    dwMS, = cconv.getCallArgs(emu, 1)
    print("Sleep: dwMillisectonds: %d" % (dwMS))
    # calling getHeap initializes a heap.  we can cheat for now.  we may need to initialize new heaps here
    time.sleep(dwMS/1000)
    emu.temu.pause = True
    emu.temu.nonstop = 0

    cconv.execCallReturn(emu, 0, 1)

def HeapCreate(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    opts, initsz, maxsz = cconv.getCallArgs(emu, 3)
    print("HeapCreate: flOptions: 0x%x dwInitialSize: 0x%x, dwMaxSize" % (opts, initsz, maxsz))
    # calling getHeap initializes a heap.  we can cheat for now.  we may need to initialize new heaps here
    cconv.execCallReturn(emu, emu.setVivTaint('MSHeap', op.va), 3)

def HeapDestroy(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    heapHandle = cconv.getCallArgs(emu, 1)
    print("HeapDestroy: 0x%x" % heapHandle)
    # calling getHeap initializes a heap.  we can cheat for now.  we may need to initialize new heaps here
    cconv.execCallReturn(emu, heapHandle, 1)

def HeapAlloc(emu, op=None):
    '''
    This is a functional heap implementation, not intended to behave in any way like 
    the MS heap or any other heap impls available.  It gives you a chunk of memory so
    the program you're playing with keeps going.
    That's it.
    dwflags is ignored completely.
    '''
    ccname, cconv = getMSCallConv(emu, op.va)
    hheap, dwflags, size = cconv.getCallArgs(emu, 3)

    heap = getHeap(emu)
    allocated_ptr = heap.malloc(size)
    print("malloc(0x%x)  => 0x%x" % (size, allocated_ptr))
    cconv.execCallReturn(emu, allocated_ptr, 3)

def HeapFree(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    hheap, dwflags, va = cconv.getCallArgs(emu, 3)
    print("FREE: 0x%x" % va)
    cconv.execCallReturn(emu, va, 3)

def HeapReAlloc(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    hheap, dwflags, existptr, size, = cconv.getCallArgs(emu, 4)

    heap = getHeap(emu)
    allocated_ptr = heap.realloc(existptr, size)
    print("HeapReAlloc(0x%x, 0x%x, 0x%x, 0x%x): 0x%x" % (hheap, dwflags, existptr, size, allocated_ptr))
    cconv.execCallReturn(emu, allocated_ptr, 4)

critical_sections = collections.defaultdict(list)
def InitializeCriticalSection(emu, op=None):
    global critical_sections
    ccname, cconv = getMSCallConv(emu, op.va)
    lpCriticalSection, = cconv.getCallArgs(emu, 1)
    print("InitializeCriticalSection(0x%x)" % (lpCriticalSection))
    critical_sections[lpCriticalSection].append(('Init', op.va))
    # do absolutely nothing but clean up
    cconv.execCallReturn(emu, 0, 1)

def EnterCriticalSection(emu, op=None):
    global critical_sections
    ccname, cconv = getMSCallConv(emu, op.va)
    lpCriticalPointer, = cconv.getCallArgs(emu, 1)
    print("EnterCriticalSection(0x%x)" % (lpCriticalPointer))
    critical_sections[lpCriticalPointer].append(('Enter',op.va))
    # do absolutely nothing but clean up
    cconv.execCallReturn(emu, 0, 1)

def LeaveCriticalSection(emu, op=None):
    global critical_sections
    ccname, cconv = getMSCallConv(emu, op.va)
    lpCriticalPointer, = cconv.getCallArgs(emu, 1)
    print("LeaveCriticalSection(0x%x)" % (lpCriticalPointer))
    critical_sections[lpCriticalPointer].append(('Leave', op.va))
    # do absolutely nothing but clean up

    cconv.execCallReturn(emu, 0, 1)

def DeleteCriticalSection(emu, op=None):
    global critical_sections
    ccname, cconv = getMSCallConv(emu, op.va)
    lpCriticalPointer, = cconv.getCallArgs(emu, 1)
    print("DeleteCriticalSection(0x%x)" % (lpCriticalPointer))
    critical_sections[lpCriticalPointer].append(('Delete', op.va))
    # do absolutely nothing but clean up

    cconv.execCallReturn(emu, 0, 1)

def InterlockedCompareExchange(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    Destination, xchgval, cmpval = cconv.getCallArgs(emu, 3)
    destval = emu.readMemValue(Destination, 4)

    print("InterlockedCompareExchange(0x%x, 0x%x, 0x%x)" % (destval, xchgval, cmpval))

    if destval == cmpval:
        emu.writeMemValue(Destination, xchgval, 4)
        destval = xchgval

    cconv.execCallReturn(emu, destval, 3)

def GetLastError(emu, op=None):
    kernel = emu.getMeta('kernel')
    ccname, cconv = getMSCallConv(emu, op.va)
    cconv.execCallReturn(emu, kernel.getLastError(), 0)

def SetLastError(emu, op=None):
    kernel = emu.getMeta('kernel')
    ccname, cconv = getMSCallConv(emu, op.va)
    last_error, = cconv.getCallArgs(emu, 1)
    kernel.setLastError(last_error)
    cconv.execCallReturn(emu, 0, 1)

def GetCurrentThreadId(emu, op=None):
    kernel = emu.getMeta('kernel')
    ccname, cconv = getMSCallConv(emu, op.va)
    print("GetCurrentThreadId()")
    cconv.execCallReturn(emu, kernel.getCurThread(), 0)

def GetCurrentProcessId(emu, op=None):
    kernel = emu.getMeta('kernel')
    ccname, cconv = getMSCallConv(emu, op.va)
    print("GetCurrentProcessId()")
    cconv.execCallReturn(emu, kernel.getCurPid(), 0)

def GetTickCount(emu, op=None):
    kernel = emu.getMeta('kernel')
    ccname, cconv = getMSCallConv(emu, op.va)
    tickcount = kernel.GetTickCount()
    print("GetTickCount()")
    cconv.execCallReturn(emu, tickcount, 0)

def GetSystemTime(emu, op=None):
    '''
    Returns a pointer to a SYSTEMTIME structure
    '''
    kernel = emu.getMeta('kernel')
    ccname, cconv = getMSCallConv(emu, op.va)
    lpSystemTimeAsFileTime, = cconv.getCallArgs(emu, 1)
    print("GetSystemTime(0x%x)" % lpSystemTimeAsFileTime)

    winktime = kernel.GetSystemTime()
    emu.writeMemoryFormat(lpSystemTimeAsFileTime, '<Q', winktime)

    cconv.execCallReturn(emu, 0, 1)

def GetSystemTimeAsFileTime(emu, op=None):
    '''
    Returns a pointer to a FILETIME structure which...
    Contains a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC).
    '''
    kernel = emu.getMeta('kernel')
    ccname, cconv = getMSCallConv(emu, op.va)
    lpSystemTimeAsFileTime, = cconv.getCallArgs(emu, 1)
    print("GetSystemTimeAsFileTime(0x%x)" % lpSystemTimeAsFileTime)

    winktime = kernel.GetSystemTimeAsFileTime()
    emu.writeMemoryFormat(lpSystemTimeAsFileTime, '<Q', winktime)

    cconv.execCallReturn(emu, 0, 1)

def SystemTimeToFileTime(emu, op=None):
    '''
    Returns a pointer to a FILETIME structure which...
    Contains a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC).
    '''
    kernel = emu.getMeta('kernel')
    ccname, cconv = getMSCallConv(emu, op.va)
    lpSystemTime, lpFileTime = cconv.getCallArgs(emu, 2)
    print("SystemTimeToFileTime(0x%x, 0x%x)" % (lpSystemTime, lpFileTime))
    # THIS IS A PROBLEM IF THEY ASSUME STACK IS CLEAN!!!!
    sometimetup = tuple([emu.readMemValue(lpSystemTime + x, 2) for x in range(0, 16, 2)]) 
    #sometime = tuple([sometimeraw[x:x+2] for x in range(0, 16, 2)])

    winktime = kernel.SystemTimeToFileTime(sometimetup)
    emu.writeMemoryFormat(lpFileTime, '<Q', winktime)

    cconv.execCallReturn(emu, 1, 2)


def QueryPerformanceCounter(emu, op=None):
    kernel = emu.getMeta('kernel')
    ccname, cconv = getMSCallConv(emu, op.va)
    lpPerformanceCount, = cconv.getCallArgs(emu, 1)
    print("QueryPerformanceCounter(0x%x)" % lpPerformanceCount)
    perfcnt = kernel.QueryPerformanceCounter()
    emu.writeMemoryFormat(lpPerformanceCount, '<Q', perfcnt)

    cconv.execCallReturn(emu, 123, 1)   # non-zero on success

def _initterm_e(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    lpFuncArrayStart, lpFuncArrayStop = cconv.getCallArgs(emu, 2)
    errno = 0

    print("_initterm_e(0x%x, 0x%x)" % (lpFuncArrayStart, lpFuncArrayStop))

    # get return value and store it...
    arryptr = lpFuncArrayStart
    while arryptr < lpFuncArrayStop:
        fnptr = emu.readMemoryPtr(arryptr)
        if fnptr:
            print("... 0x%x" % fnptr)
            if not emu.isValidPointer(fnptr):
                errno = -1
            else:
                # emulate each non-null function pointer
                emu.doPush(0x82345678)
                emu.setProgramCounter(fnptr)
                emu.temu.runStep(silent=emu.temu.silent, pause=False, finish=0x82345678)

                sanitychk = emu.getProgramCounter()
                if sanitychk != 0x82345678:
                    raise Exception("_initterm_e() stack craziness.  Investigate! PC=0x%x", sanitychk)

                retval = cconv.getReturnValue(emu)
                if retval != 0:
                    # in _e, we return any int value of the functions (as errors)
                    errno = retval
                    break

        arryptr += emu.psize
    
    print("_initterm_e(0x%x, 0x%x) COMPLETE" % (lpFuncArrayStart, lpFuncArrayStop))
    cconv.execCallReturn(emu, errno, 2)

def _initterm(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    lpFuncArrayStart, lpFuncArrayStop = cconv.getCallArgs(emu, 2)
    errno = 0

    print("_initterm(0x%x, 0x%x)" % (lpFuncArrayStart, lpFuncArrayStop))

    # get return value and store it...
    arryptr = lpFuncArrayStart
    while arryptr < lpFuncArrayStop:
        fnptr = emu.readMemoryPtr(arryptr)
        if fnptr:
            print("... 0x%x" % fnptr)
            if not emu.isValidPointer(fnptr):
                errno = -1
            else:
                # emulate each non-null function pointer
                cconv.setupCall(emu, ra=0x82345678)

                emu.setProgramCounter(fnptr)
                emu.temu.runStep(silent=emu.temu.silent, pause=False, finish=0x82345678)

                sanitychk = emu.getProgramCounter()
                if sanitychk != 0x82345678:
                    raise Exception("_initterm() stack craziness.  Investigate! PC=0x%x", sanitychk)

        arryptr += emu.psize
    
    print("_initterm(0x%x, 0x%x) COMPLETE" % (lpFuncArrayStart, lpFuncArrayStop))
    cconv.execCallReturn(emu, errno, 2)

def __dllonexit(emu, op=None):
    kernel = emu.getMeta('kernel')
    ccname, cconv = getMSCallConv(emu, op.va)
    func, pbegin, pend = cconv.getCallArgs(emu, 3)
    print("__dllonexit(0x%x, 0x%x, 0x%x)" % (func, pbegin, pend))

    retva = cconv.getReturnAddress(emu)
    kernel._dllonexit(retva, func, pbegin, pend)

    cconv.execCallReturn(emu, func, 3)

# TODO: wrap this into a TLS object and strap it into the emulator like we do with the Heap
tls_idxs = []
tls_next_idx = 100
tls_data = collections.defaultdict(list)

def rtTlsAlloc():
    global tls_idxs, tls_next_idx, tls_data
    idx = tls_next_idx
    tls_idxs.append(idx)
    tls_next_idx+= 1
    return idx

def rtTlsGetValue(slot):
    '''
    Returns None if nothing exists. By design.
    '''
    global tls_data
    if len(tls_data[slot]):
        return tls_data[slot][-1]

    print("rtTlsGetValue(%d) returning None, sorry..." % slot)


def rtTlsSetValue(slot, data):
    global tls_data
    tls_data[slot].append(data)
    return 1


def TlsAlloc(emu, op=None):
    # should we track this in the emulator?
    ccname, cconv = getMSCallConv(emu, op.va)
    print("TlsAlloc()")
    cconv.execCallReturn(emu, rtTlsAlloc(), 0)

def TlsGetValue(emu, op=None):
    global tls_data
    ccname, cconv = getMSCallConv(emu, op.va)
    slot, = cconv.getCallArgs(emu, 1)

    tlsval = rtTlsGetValue(slot)
    print("TlsGetValue(%d): found %r" % (slot, tlsval))

    if tlsval is None:  # do this here since we have an op and emu already, and it makes sense
        tlsval = emu.setVivTaint('TlsGetValue::Slot at 0x%x' % op.va, slot)
        rtTlsSetValue(slot, tlsval)

    cconv.execCallReturn(emu, tlsval, 1)

def TlsSetValue(emu, op=None):
    global tls_data
    ccname, cconv = getMSCallConv(emu, op.va)
    slot, data = cconv.getCallArgs(emu, 2)


    print("TlsSetValue(%d, %r):" % (slot, data))
    cconv.execCallReturn(emu, rtTlsSetValue(slot, data), 2)


def CompareStringEx(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    lpLocaleName, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2, lpVersionInfo, \
            lpRsrvd, lParam = cconv.getCallArgs(emu, 9)
    result = doWin32StringCompare(emu, op, Locale, dwCmpFlags, lpString1, cchCount1, \
            lpString2, cchCount2, lpVersionInfo, lpRsrvd, lParam, charsize=2)

    cconv.execCallReturn(emu, result, 9)

def CompareStringW(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    Locale, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2 = cconv.getCallArgs(emu, 6)
    result = doWin32StringCompare(emu, op, Locale, dwCmpFlags, lpString1, cchCount1, \
            lpString2, cchCount2, 0,0,0, charsize=2)

    cconv.execCallReturn(emu, result, 6)

def CompareStringA(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    Locale, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2 = cconv.getCallArgs(emu, 6)
    result = doWin32StringCompare(emu, op, Locale, dwCmpFlags, lpString1, cchCount1, \
            lpString2, cchCount2, 0,0,0, charsize=2)

    cconv.execCallReturn(emu, result, 6)


def testPolicy(mode, fs_policy):
    perms = 0
    if b'r' in mode:
        perms |= MM_READ

    if b'a' in mode or b'+' in mode:
        perms |= MM_READ | MM_WRITE

    if b'w' in mode:
        perms |= MM_WRITE

    return (fs_policy & perms) == perms

ENOENT = 2
EACCES = 13
ENOTDIR = 20
EISDIR = 21

def fopen(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    pFilename, pMode = cconv.getCallArgs(emu, 2)

    filename = emu.readMemString(pFilename)
    mode = emu.readMemString(pMode)
    print("fopen(%r, %r)" % (filename, mode))

    # check policy.  if this mode is not allowed, prompt the user
    uinp = None
    kernel = emu.getMeta('kernel')
    if testPolicy(mode, kernel.fs_policy):
        uinp = 'Y'

    elif not kernel.fs_polprompt:
        # we're *not* to prompt, just fail.
        uinp = 'N'

    while uinp not in ('Y', 'N'):
        uinp = input("Are you sure you want to allow this?  (Y/N)")

    # once we tested policy and asked the user for their permission, continue accordinly
    if uinp == 'N':
        retval = EACCES

    else:

        retval = 0

        try:
            retval, myfile = kernel.fopen(filename, mode)

        except FileNotFoundError:
            kernel.errno = ENOENT

        except IsADirectoryError:
            kernel.errno = EISDIR

        except:
            print("fopen:  unhandled exception:")
            import traceback
            traceback.print_exc()
            uinp = input("Press Enter to Continue or 'q' to quit ")
            if uinp.startswith('q'):
                emu.temu.resetNonstop()

        print("DONE:  %r   %r" % (retval, myfile))

    cconv.execCallReturn(emu, retval, 2)

def fread(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    pBuffer, size, count, stream = cconv.getCallArgs(emu, 4)
    print("fread(0x%x, 0x%x, 0x%x, %r)" % (pBuffer, size, count, stream))

    length = size * count

    kernel = emu.getMeta('kernel')
    data = kernel.fds[stream].read(length)
    if len(data) > 100:
        print("  == %r..." % data[:100])
    else:
        print("  == %r" % data)
    emu.writeMemory(pBuffer, data)
    retval = len(data)

    cconv.execCallReturn(emu, retval, 4)

def fwrite(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    pBuffer, size, count, stream = cconv.getCallArgs(emu, 4)
    print("fwrite(0x%x, 0x%x, 0x%x, %r)" % (pBuffer, size, count, stream))

    length = size * count

    kernel = emu.getMeta('kernel')
    data = emu.readMemory(pBuffer, length)
    if len(data) > 100:
        print("  == %r..." % data[:100])
    else:
        print("  == %r" % data)
    
    kernel.fds[stream].write(data)
    retval = len(data)

    cconv.execCallReturn(emu, retval, 4)

def fclose(emu, op=None):
    ccname, cconv = getLibcCallConv(emu)
    stream, = cconv.getCallArgs(emu, 1)
    print("fclose(%r)" % (stream))

    kernel = emu.getMeta('kernel')
    kernel.fds[stream].close()

    cconv.execCallReturn(emu, 0, 1)

def isspace(emu, op=None):
    '''
    '''
    ccname, cconv = getLibcCallConv(emu)
    c, = cconv.getCallArgs(emu, 1)
    print("isspace(0x%x)" % (c))

    retval = (c in (0x9, 0xa, 0xb, 0xc, 0xd, 0x20))

    cconv.execCallReturn(emu, retval, 4)


class FakeFile:
    '''
    FakeFile allows us to use a File-like object for files only defined in the 
    TestEmulator as bytes() objects.  Behaves similar to _io.BufferedReader.
    '''
    def __init__(self, filename, data=b'', mode='rb', off=0):
        self.filename = filename
        self._filenum = None
        self.closed = False
        self.data = data
        self.off = off

    def close(self):
        self.closed = True

    def flush(self):
        pass

    def fileno(self):
        return self._filenum

    def peek(self):
        if self.closed:
            raise ValueError("FakeFile is Closed")

        return self.data[self.off:]

    def read(self, length=None):
        if b'r' not in self.mode and\
                b'+' not in self.mode:
            raise io.UnsupportedOperation("Writing to a file opened for read")

        if self.closed:
            raise ValueError("FakeFile is Closed")

        if length:
            retval =  self.data[self.off:self.off+length]
            self.off += length
            return retval

        retval = self.data[self.off:]
        self.off = len(self.data)
        return retval
        
    def seek(self, offset):
        if self.closed:
            raise ValueError("FakeFile is Closed")

        self.off = offset

    def tell(self):
        if self.closed:
            raise ValueError("FakeFile is Closed")

        return self.off

    def write(self, data=b''):
        if b'w' not in self.mode and\
                b'a' not in self.mode and\
                b'+' not in self.mode:
            raise io.UnsupportedOperation("Writing to a file opened for read")

        if self.closed:
            raise ValueError("FakeFile is Closed")

        self.data = self.data[:self.off] + data + self.data[self.off + len(data):]

    def _save(self, filename=None):
        '''
        Allow the saving of the updated file to a real file.
        '''
        if not filename:
            filename = self.filename

        open(filename, 'wb').write(self.data)


def findInternalPath(kernel, libFileName, casein=False, matchFnOnly=True):
    if kernel is not None:
        sep = kernel.sep

    else:
        sep = os.sep

    ulibFileName = libFileName.upper()
    
    for filepath in kernel.fs:
        # carve up the path and filename info
        meta = filepath.rsplit(sep, 1)
        if len(meta) == 2:
            path, fname = meta
        else:
            path = '.'
            fname = meta

        # if we want to find a file in the path, or match an actual full path:
        if matchFnOnly:
            f = fname
        else:
            f = filepath

        uf = f.upper()

        if casein:
            if uf == ulibFileName:
                return(sep.join([path, fname]))

        elif f == libFileName:
            return(sep.join([path, fname]))

    raise FileNotFoundError(libFileName)

def findExtPath(filepath, libFileName, casein=False, kernel=None, matchFnOnly=True):
    '''
    helper function to dig through paths and find a file

    filepath is a list of directories
    libFileName is a filename we're looking for
    casein means filenames are not case-sensitive.
    matchFnOnly means we're searching for a File.  Otherwise, we're matching an exact path

    Returns a Fake path and a Real path (for the current OS file-path)
        Fake path is helpful for GetModuleFileName*
        Real path is helpful for actually opening the file

    '''
    ossep = os.sep.encode('utf-8')

    if kernel is not None:
        sep = kernel.sep

    else:
        sep = ossep

    ulibFileName = libFileName.upper()

    for pathpart, fakepart in filepath:
        for fname in os.listdir(pathpart):
            if matchFnOnly:
                f = fname
            else:
                f = sep.join([fakepart, fname])

            uf = f.upper()
            if casein:
                if uf == ulibFileName:
                    return(sep.join([fakepart, fname]), ossep.join([pathpart, fname]))

            elif f == libFileName:
                return(sep.join([fakepart, fname]), ossep.join([pathpart, fname]))

    raise FileNotFoundError(libFileName)

def FreeLibrary(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    hLibModule, = cconv.getCallArgs(emu, 1)
    fname = emu.vw.getFileByVa(hLibModule)

    print("FreeLibrary(0x%x)  (%r)" % (hLibModule, fname))
    kernel = emu.getMeta('kernel')
    kernel.freeLibrary(hLibModule, fname)

    cconv.execCallReturn(emu, hLibModule, 1)


def LoadLibraryExA(emu, op=None):
    kernel = emu.getMeta('kernel')
    ccname, cconv = getMSCallConv(emu, op.va)
    lpLibFileName, hFile, dwFlags = cconv.getCallArgs(emu, 3)
    libFileName = emu.readMemString(lpLibFileName)

    # check through path(s)
    result = None
    go = False

    # slice off path information
    if b'\\' in libFileName:
        lparts = libFileName.split(b'\\')
        libFileName = lparts[-1]
    

    # we need to load our library, and each dependency library that isn't already loaded
    todo = [libFileName]
    while todo:
        libFileName = todo.pop()

        # get the name as it would appear in Viv's memory maps:
        normfn = emu.vw.normFileName(libFileName.decode('utf-8'))

        # go until it's loaded or we tell it to bugger off.
        while result is None:
            try:
                result = emu.vw.parseExpression(normfn)
                print("Map loaded...")
                # register with the Kernel that we're loading (in the future, more LoadLibrary functionality may move there)
                kernel.loadLibrary(result, normfn)

                break

            except ExpressionFail as e:
                print(e)
                # if we don't have it already loaded and resolvable in the workspace
                # we must load it
           
            try:
                filepath = findExtPath(emu.temu.filepath, libFileName, kernel=kernel)
                if not filepath:
                    filepath = input("PLEASE ENTER THE PATH FOR (%r) or 'None': " % libFileName)
                    if filepath == "None":
                        result = 0
                        break

                print("Loading...")
                normfn = emu.vw.loadFromFile(filepath)
                go = True
                print("Loaded")

                # if we have it setup, run vw.analyze()
                if emu.getMeta("AnalyzeLoadLibraryLoads", False):
                    print("Analyzing...")
                    emu.vw.analyze()


                libva = emu.vw.parseExpression(normfn)

                # merge the imported memory maps from the Workspace into the emu
                print("Sync VW maps to EMU...")
                syncEmuWithVw(emu.vw, emu)
                kernel.loadLibrary(result, normfn)
                print("Synced")

            except KeyboardInterrupt:
                break

            except Exception as e:
                print(e)

        # run Library Init routine (__entry)
        ret = emu.readMemoryPtr(emu.getStackCounter())  # FIXME: this only works on archs where RET is pushed to the stack
        init = emu.vw.parseExpression(normfn + ".__entry")

        if init:
            print("RUNNING LIBRARY INITIALIZER: %r" % libFileName)
            ccname, cconv = getMSCallConv(emu, init)
            cconv.allocateCallSpace(emu, 3)
            # set RET to 0x8831337
            ret = emu.writeMemoryPtr(emu.getStackCounter(), 0x8831337)

            instance = result
            reason = DLL_PROCESS_ATTACH  # initialize
            reserved = 0
            cconv.setCallArgs(emu, [instance, reason, reserved])
    
            emu.setProgramCounter(init)
            emu.temu.runStep(silent=emu.temu.silent, pause=False, runTil=0x8831337)

            print("COMPLETED LIBRARY INITIALIZER: %r" % libFileName)
        else:
            print("No Library Init found, just returning")

    #import envi.interactive as ei; ei.dbg_interact(locals(), globals())
    cconv.execCallReturn(emu, result, 3)

DLL_PROCESS_DETACH = 0
DLL_PROCESS_ATTACH = 1
DLL_THREAD_ATTACH = 2
DLL_THREAD_DETACH = 3

def GetProcAddress(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    hModule, lpProcName = cconv.getCallArgs(emu, 2)
    print("GetProcAddress(0x%x, 0x%x)" % (hModule, lpProcName))

    result = 0
    try:
        if hModule and lpProcName:
            libmap = emu.getMemoryMap(hModule)
            libname = libmap[3]
            ProcName = emu.readMemString(lpProcName).decode('utf-8')
            fullname = "%s.%s" % (libname, ProcName)
            print("     ==> (%r)" % (fullname))
            result = emu.vw.parseExpression(fullname)
    except Exception as e:
        print("Error: %r" % e)

    cconv.execCallReturn(emu, result, 2)


def GetModuleFileNameA(emu, op=None):
    '''
    kernel32.GetModuleFileNameA
    '''
    kernel = emu.getMeta('kernel')
    ccname, cconv = getMSCallConv(emu, op.va)
    hModule, lpFilename, nSize = cconv.getCallArgs(emu, 3)
    print("GetModuleFilenameA(0x%x, 0x%x, 0x%x)" % (hModule, lpFilename, nSize))

    if hModule:
        curname = emu.vw.getFileByVa(hModule).encode('utf8')
        curname += b'.dll'
    else:
        curname = b"Filename.exe"
    print("GetModuleFileNameA(%r)" % curname)

    # search internal data structures for this module's path
    print("kernel: %r" % kernel)
    filepath = findInternalPath(kernel, curname, casein=True)

    # if we don't find it internally, check the filesystem(s) mapped in through the "kernel"
    if not filepath:
        filepath = findExtPath(emu.temu.filepath, curname, casein=True, kernel=kernel)

    print("GetModuleFileNameA() -> %r" % filepath)

    if filepath:
        curname = filepath

    else:
        uinp = input("  (%r):" % curname)
        if len(uinp):
            curname = uinp

    retname = curname
    
    if retname[-1] != b'\0':
        retname += b'\0'

    if len(retname) > nSize:
        retname = retname[:nSize-1] + b'\0' # WinXP: not NULL terminated if too big

    result = len(retname.replace(b'\0', b'')) # len without NULL

    emu.writeMemory(lpFilename, retname)

    cconv.execCallReturn(emu, result, 3)

def CreateMutexA(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    lpMutexAttributes, bInitialOwner, lpName = cconv.getCallArgs(emu, 3)
    name = b''

    # this is a rough skelleton for hacking purposes...
    heap = getHeap(emu)
    newmutex = heap.malloc(32) # guess at some size

    if lpName:
        name = emu.readMemString(lpName)

    kernel = emu.getMeta('kernel')
    kernel.mutexes[newmutex] = (op.va, lpMutexAttributes, bInitialOwner, name)
    print("CreateMutexA: (0x%x, %r, 0x%x, 0x%x)" % (newmutex, name, bInitialOwner, lpMutexAttributes))
    emu.writeMemory(newmutex, b"Mutex: %r" % name)

    cconv.execCallReturn(emu, newmutex, 3)

def ReleaseMutex(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    hMutex, = cconv.getCallArgs(emu, 1)

    kernel = emu.getMeta('kernel')
    mutup = kernel.mutexes.get(hMutex)

    if mutup is None:
        #do some error thing here
        print("FAILED (MutexNotFoundInKernel)   ReleaseMutex(0x%x)" % hMutex)
    else:
        op.va, lpMutexAttributes, bInitialOwner, lpName = mutup
        mutdata = emu.readMemory(hMutex, 32)
        mutdata = mutdata[:-10] + b"Released\0\0"

        emu.writeMemory(hMutex, mutdata)
        print("ReleaseMutex(0x%x)" % hMutex)

    cconv.execCallReturn(emu, 0, 1)




WAIT_ABANDONED = 0x00000080
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
WAIT_FAILED = 0xFFFFFFFF
def WaitForSingleObject(emu, op=None):
    '''
    This could be much more...
    '''
    kernel = emu.getMeta('kernel')
    ccname, cconv = getMSCallConv(emu, op.va)
    hHandle, dwMillis = cconv.getCallArgs(emu, 2)

    objbytes = emu.readMemory(hHandle, 32)        # FIXME: make this more meaningful
    print("WaitForSingleObject(0x%x, %d)  => %r" % (hHandle, dwMillis, objbytes))

    # write "Acquired"
    mutup = kernel.mutexes.get(hHandle)

    if mutup is None:
        pass    # not a Mutex.  TODO: unify kernel interface for WFSO-able objs
    else:
        op.va, lpMutexAttributes, bInitialOwner, lpName = mutup
        mutdata = emu.readMemory(hHandle, 32)
        mutdata = mutdata[:-10] + b"Acquired\0\0"

        emu.writeMemory(hHandle, mutdata)

    input()
    
    # TODO: roll through supported object types and check/reserve them
    # Mutexes from the WinKernel
    result = WAIT_OBJECT_0

    cconv.execCallReturn(emu, result, 2)

def CloseHandle(emu, op=None):
    '''
    per MSDN:
    The CloseHandle function closes handles to the following objects:
        Access token
        Communications device
        Console input
        Console screen buffer
        Event
        File
        File mapping
        I/O completion port
        Job
        Mailslot
        Memory resource notification
        Mutex
        Named pipe
        Pipe
        Process
        Semaphore
        Thread
        Transaction
        Waitable timer
    '''
    ccname, cconv = getMSCallConv(emu, op.va)
    hHandle, = cconv.getCallArgs(emu, 1)
    emu.getMeta('CloseHandle', []).append((op.va, hHandle))
    print("CloseHandle(0x%x)" % hHandle)

    cconv.execCallReturn(emu, hHandle, 1)

def EncodePointer(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    ptr, = cconv.getCallArgs(emu, 1)
    print("EncodePointer(0x%x) => 0x%x" % (ptr, ptr))

    cconv.execCallReturn(emu, ptr, 1)

def DecodePointer(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    ptr, = cconv.getCallArgs(emu, 1)
    print("DecodePointer(0x%x) => 0x%x" % (ptr, ptr))

    cconv.execCallReturn(emu, ptr, 1)

def _amsg_exit(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    val, = cconv.getCallArgs(emu, 1)
    print("_amsg_exit(0x%x) - the Process Should Now TERMINATE!" % (val))
    emu.temu.resetNonstop()

    cconv.execCallReturn(emu, val, 1)

def _lock(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    val, = cconv.getCallArgs(emu, 1)
    print("_lock(%r)" % (val))

    cconv.execCallReturn(emu, val, 0)

def _unlock(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    val, = cconv.getCallArgs(emu, 1)
    print("_unlock(%r)" % (val))

    cconv.execCallReturn(emu, val, 0)


def dupWorkspace(vw):
    newvw = viv_cli.VivCli()
    for evt, einfo in emu.vw._event_list:
        newvw._fireEvent(evt, einfo)

    for amod in vw.amods:
        newvw.amods.append(amod)
    for amodnm in vw.amodlist:
        newvw.amodlist.append(amodnm)

    for fmod in vw.fmods:
        newvw.fmods.append(fmod)
    for fmodnm in vw.fmodlist:
        newvw.fmodlist.append(fmodnm)

    return newvw

def syncEmuWithVw(vw, emu, name=None, refresh=False):
    '''
    make Emulator maps to match those in the Workspace.
    if name is specified, only maps with that name will be copied
    if refresh, if maps exist, copy the contents from the Workspace (like a clean load)
    '''
    print("Sync'ing Emulator memory maps from Workspace")
    for mmva, mmsz, mmperm, mmname in vw.getMemoryMaps():
        done = False

        # if we're specific about the name, skip all other maps
        if name is not None and name != mmname:
            continue

        # if the emulator map already exists
        if emu.isValidPointer(mmva):
            if not refresh:
                print("skipping map at 0x%x (%r) because map already exists" % (mmva, mmname))
                continue

            else:
                emu._supervisor = True
                emu.writeMemory(mmva, vw.readMemory(mmva, mmsz))
                emu._supervisor = False
                done = True

        # if we haven't already refreshed, we must need to add the memory map
        if not done:
            emu.addMemoryMap(mmva, mmperm, mmname, vw.readMemory(mmva, mmsz))


CSTR_FAILURE = 0
CSTR_LESS_THAN = 1
CSTR_EQUAL = 2
CSTR_GREATER_THAN = 3

def doWin32StringCompare(emu, op, \
        Locale, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2, \
        lpVersionInfo, lpReserved, lParam, charsize=1):

    if dwCmpFlags:
        print("CompareStringEx with flags %x, unsupported." % dwCmpFlags)

    idx = 0
    result = 0
    while True:
        if (cchCount1 != -1 and idx > cchCount1):
            if cchCount1 == cchCount2:
                return CSTR_EQUAL
            if cchCount2 == -1 and val2[0] == 0:
                return CSTR_EQUAL
            return CSTR_GREATER # ? if str1 is done and str2 isn't?

        if (cchCount2 != -1 and idx > cchCount2):
            if cchCount1 == cchCount2:
                return CSTR_EQUAL
            if cchCount1 == -1 and val1[0] == 0:
                return CSTR_EQUAL
            return CSTR_LESS_THAN   # ? if str2 is done and str1 isn't?

        val1 = emu.readMemory(lpString1 + idx, charsize)
        val2 = emu.readMemory(lpString2 + idx, charsize)
        # do any conversions necessary (skipping for now, i'm feeling lucky)

        # do comparison.  this version is cheating:
        for x in range(charsize):
            val1part = val1[x]
            val2part = val2[x]
            result = val1part - val2part
            if result:
                return result + 2   # MS likes 1,2,3 where 0 is failure

        idx += charsize

    return CSTR_FAILURE


import re
def tokenizeFmtStr(fmt):
    cfmt=b'''\
    (                                  # start of capture group 1
    %                                  # literal "%"
    (?:                                # first option
    (?:[-+0 #]{0,5})                   # optional flags
    (?:\d+|\*)?                        # width
    (?:\.(?:\d+|\*))?                  # precision
    (?:h|l|ll|w|I|I32|I64)?            # size
    [cCdiouxXeEfgGaAnpsSZ]             # type
    ) |                                # OR
    %%)                                # literal "%%"
    '''

    #for line in lines.splitlines():
    #    print '"{}"\n\t{}\n'.format(line,
    #           tuple((m.start(1), m.group(1)) for m in re.finditer(cfmt, line, flags=re.X)))

    return tuple((m.start(1), m.group(1)) for m in re.finditer(cfmt, fmt, flags=re.X))

def vsnprintf(emu, op=None):
    '''
    Simplistic, but good enough for most government work...
    '''
    stackDump(emu)
    ccname, cconv = getMSCallConv(emu, op.va, 'cdecl')
    s, n, fmt, args = cconv.getCallArgs(emu, 4)
    outfmt = emu.readMemString(fmt)

    off = 0
    arglist = []
    if b'%' in outfmt:
        bits = emu.readMemoryPtr(args + off)
        if emu.getMemoryMap(bits):
            arglist.append(emu.readMemString(bits))
        else:
            arglist.append(bits)
        off += 4

    while True:
        #print(outfmt, tuple(arglist))
        try:
            out = outfmt % tuple(arglist)
            break
        except TypeError:
            bits = emu.readMemoryPtr(args + off)
            if emu.getMemoryMap(bits):
                arglist.append(emu.readMemString(bits))
            else:
                arglist.append(bits)
            off += 4

    emu.writeMemory(s, out[:n])
    result = len(out)

    input("vsnprintf: %r" % out)
    cconv.execCallReturn(emu, result, 4)
   

def vsprintf_s(emu, op=None):
    '''
    Simplistic, but good enough for most government work...
    '''
    stackDump(emu)
    ccname, cconv = getMSCallConv(emu, op.va, 'cdecl')
    s, n, fmt, args = cconv.getCallArgs(emu, 4)
    outfmt = emu.readMemString(fmt)

    off = 0     # TODO: convert to index and do the math on read
    arglist = []
    lastfmtoff = 0

    out = []
    for fmtoff, fmtbit in tokenizeFmtStr(outfmt):
        realstr = outfmt[lastfmtoff:fmtoff]
        out.append(realstr)
        lastfmtoff = fmtoff + len(fmtbit)

        print(fmtoff, fmtbit)

        bits = emu.readMemoryPtr(args + off)
        if fmtbit.endswith(b's'):
            strpart = emu.readMemString(bits)
            out.append(fmtbit % strpart)
            
        elif b'll' in fmtbit:
            fmtbit = fmtbit.replace(b'll', b'')
            # number bigger
            bits = emu.readMemValue(args + off, 8)
            off += 4    # we're reading a 64-bit number??
            out.append(fmtbit % bits)

        elif b'l' in fmtbit:
            fmtbit = fmtbit.replace(b'l', b'')
            out.append(fmtbit % bits)

        elif fmtbit.endswith(b'p'):
            fmtbit = fmtbit.replace(b'p', b'x')
            out.append(fmtbit % bits)

        else:
            out.append(fmtbit % bits)

        off += 4

        #bits = emu.readMemoryPtr(args + off)
        #if emu.getMemoryMap(bits):
        #    arglist.append(emu.readMemString(bits))     # ?
        #else:
        #    arglist.append(bits)
        #off += 4

    #while True:
    #    #print(outfmt, tuple(arglist))
    #    try:
    #        out = outfmt % tuple(arglist)
    #        break
    #    except TypeError:
    #        bits = emu.readMemoryPtr(args + off)
    #        if emu.getMemoryMap(bits):
    #            arglist.append(emu.readMemString(bits))
    #        else:
    #            arglist.append(bits)
    #        off += 4

    outstr = b''.join(out)[:n]
    emu.writeMemory(s, outstr)
    result = len(outstr)

    input("vsprintf_s: %r" % outstr)
    cconv.execCallReturn(emu, result, 4)
   

def getenv_s(emu, op=None):
    '''
    Get Environment Variables....
    Since we don't have any environment variables, 
    '''
    ccname, cconv = getMSCallConv(emu, op.va)
    pRetVal, buff, numElem, varnameptr = cconv.getCallArgs(emu, 4)

    # grab some fake Environment variable string...
    temu = emu.temu
    vw = temu.vw
    varname = temu.emu.readMemString(varnameptr)
    print("getenv_s(0x%x, 0x%x, 0x%x, %r)" % (pRetVal, buff, numElem, varname))

    os = vw.getMeta('Platform')
    if os in ('windows', 'winkern'):
        # case-insensitive... everything must be UPPERs
        varname = varname.upper()

    # lookup the env var:
    val = temu.environment.get(varname)

    # figure out how to return
    if not pRetVal:
        # can't actually put any meaningful response.
        print("no pRetVal! EINVAL")
        result = EINVAL

    elif val is None:
        # throw a tantrum, couldn't find it mom!
        emu.writeMemoryPtr(pRetVal, 0)
        result = EINVAL
        print("couldn't find %r! EINVAL" % varname)

    else:
        # found it...
        if not buff or numElem == 0:
            # just return the size requirements
            emu.writeMemoryPtr(pRetVal, len(val))

        else:
            # write out as much as we can...
            emu.writeMemory(buff, val[:numElem])
        result = 0

    cconv.execCallReturn(emu, result, 0)

INVALID_FILE_ATTRIBUTES = -1
def GetFileAttributesA(emu, op=None):
    '''
    Return attributes of a file or directory.
    '''
    ccname, cconv = getMSCallConv(emu, op.va)
    lpFileName, = cconv.getCallArgs(emu, 1)
    filename = emu.readMemString(lpFileName).upper()

    fsentry = emu.temu.fs.get(filename)
    if not fsentry:
        result = INVALID_FILE_ATTRIBUTES

    else:
        lstat, fdata = fsentry
        result = lstat

    cconv.execCallReturn(emu, result, 1)

def SetErrorMode(emu, op=None):
    '''
    Sets Error mode for the process
    '''
    kernel = emu.getMeta('kernel')
    ccname, cconv = getMSCallConv(emu, op.va)
    lastmode = kernel.errormode
    kernel.errormode, = cconv.getCallArgs(emu, 1)

    cconv.execCallReturn(emu, lastmode, 1)

def GetErrorMode(emu, op=None):
    '''
    Return attributes of a file or directory.
    '''
    kernel = emu.getMeta('kernel')
    ccname, cconv = getMSCallConv(emu, op.va)

    cconv.execCallReturn(emu, kernel.errormode, 0)


import_map = {
        '*.syslog': syslog,
        '*.malloc': malloc,
        '*.calloc': calloc,
        '*.free': free,
        '*.realloc': realloc,
        '*.strlen': strlen,
        '*.strcmp': strcmp,
        '*.strncmp': strncmp,
        '*.strcat': strcat,
        '*.strcpy': strcpy,
        '*.strncpy': strncpy,
        '*._strdup': strdup,
        '*.strdup': strdup,
        '*.memcpy': memcpy,
        '*.memcpy_s': memcpy_s,
        '*.memset': memset,
        'kernel32.Sleep': Sleep,
        'kernel32.HeapAlloc': HeapAlloc,
        'kernel32.HeapFree': HeapFree,
        'kernel32.HeapReAlloc': HeapReAlloc,
        'kernel32.HeapDestroy': HeapDestroy,
        'kernel32.HeapCreate': HeapCreate,     # malloc takes care of this
        'kernel32.InitializeCriticalSection': InitializeCriticalSection,
        'kernel32.EnterCriticalSection': EnterCriticalSection,
        'kernel32.LeaveCriticalSection': LeaveCriticalSection,
        'kernel32.DeleteCriticalSection': DeleteCriticalSection,
        'kernel32.InterlockedCompareExchange': InterlockedCompareExchange,
        'kernel32.GetLastError': GetLastError,
        'kernel32.SetLastError': SetLastError,
        'kernel32.TlsAlloc': TlsAlloc,
        'kernel32.TlsGetValue': TlsGetValue,
        'kernel32.TlsSetValue': TlsSetValue,
        'kernel32.GetCurrentThreadId': GetCurrentThreadId,
        'kernel32.GetCurrentProcessId': GetCurrentProcessId,
        'kernel32.GetTickCount': GetTickCount,
        'kernel32.GetSystemTime': GetSystemTime,
        'kernel32.GetSystemTimeAsFileTime': GetSystemTimeAsFileTime,
        'kernel32.SystemTimeToFileTime': SystemTimeToFileTime,
        'kernel32.QueryPerformanceCounter': QueryPerformanceCounter,
        'kernel32.CompareStringW': CompareStringW,
        'kernel32.CompareStringA': CompareStringA,
        'kernel32.GetFileAttributesA': GetFileAttributesA,
        'kernel32.SetErrorMode': SetErrorMode,
        'kernel32.GetErrorMode': GetErrorMode,
        'kernel32.FreeLibrary': FreeLibrary,
        'kernel32.LoadLibraryExA': LoadLibraryExA,  # this is the yucky one
        'kernel32.GetProcAddress': GetProcAddress,  # tied to LoadLibrary
        'kernel32.GetModuleFileNameA': GetModuleFileNameA,
        'kernel32.CreateMutexA': CreateMutexA,
        'kernel32.ReleaseMutex': ReleaseMutex,
        'kernel32.WaitForSingleObject': WaitForSingleObject,
        'kernel32.CloseHandle': CloseHandle,
        'kernel32.EncodePointer': EncodePointer,
        'kernel32.DecodePointer': DecodePointer,
        'ntdll._vsnprintf': vsnprintf,
        'msvcr100._lock': _lock,
        'msvcr100._unlock': _unlock,
        'msvcr100.__dllonexit': __dllonexit,
        'msvcr100.getenv_s': getenv_s,
        'msvcr100.calloc': calloc,
        'msvcr100.strncpy_s': strncpy_s,
        'msvcr100.strncat_s': strncat_s,
        'msvcr100.strtok_s': strtok_s,
        'msvcr100.strrchr': strrchr,
        'msvcr100.strncmp': strncmp,
        'msvcr100.free': free,
        'msvcr100._initterm': _initterm,
        'msvcr100._initterm_e': _initterm_e,
        #'msvcr100._malloc_crt': _malloc_crt,
        'msvcr100._malloc_crt': malloc,
        'msvcr100._strdup': strdup,
        'msvcr100.??2@YAPAXI@Z': HeapAlloc,
        'msvcr100.??3@YAPAXI@Z': HeapFree,
        'msvcr100.vsprintf_s': vsprintf_s,
        'msvcr100._amsg_exit': _amsg_exit,
        'msvcr100.fopen': fopen,
        'msvcr100.fread': fread,
        'msvcr100.fwrite': fwrite,
        'msvcr100.fclose': fclose,
        'msvcr100.isspace': isspace,
        }


class win32const:
    FILE_ATTRIBUTE_ARCHIVE = 32 #(0x20) A file or directory that is an archive file or directory. Applications typically use this attribute to mark files for backup or removal .
    FILE_ATTRIBUTE_COMPRESSED = 2048 #(0x800) A file or directory that is compressed. For a file, all of the data in the file is compressed. For a directory, compression is the default for newly created files and subdirectories.
    FILE_ATTRIBUTE_DEVICE = 64 #(0x40) This value is reserved for system use.
    FILE_ATTRIBUTE_DIRECTORY = 16 #(0x10) The handle that identifies a directory.
    FILE_ATTRIBUTE_ENCRYPTED = 16384 #(0x4000) A file or directory that is encrypted. For a file, all data streams in the file are encrypted. For a directory, encryption is the default for newly created files and subdirectories.
    FILE_ATTRIBUTE_HIDDEN = 2 #(0x2) The file or directory is hidden. It is not included in an ordinary directory listing.
    FILE_ATTRIBUTE_INTEGRITY_STREAM = 32768 #(0x8000) The directory or user data stream is configured with integrity (only supported on ReFS volumes). It is not included in an ordinary directory listing. The integrity setting persists with the file if it's renamed. If a file is copied the destination file will have integrity set if either the source file or destination directory have integrity set.  Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP: This flag is not supported until Windows Server 2012.
    FILE_ATTRIBUTE_NORMAL = 128 #(0x80) A file that does not have other attributes set. This attribute is valid only when used alone.
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 8192 #(0x2000) The file or directory is not to be indexed by the content indexing service.
    FILE_ATTRIBUTE_NO_SCRUB_DATA = 131072 #(0x20000) The user data stream not to be read by the background data integrity scanner (AKA scrubber). When set on a directory it only provides inheritance. This flag is only supported on Storage Spaces and ReFS volumes. It is not included in an ordinary directory listing.  Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP: This flag is not supported until Windows 8 and Windows Server 2012.
    FILE_ATTRIBUTE_OFFLINE = 4096 #(0x1000) The data of a file is not available immediately. This attribute indicates that the file data is physically moved to offline storage. This attribute is used by Remote Storage, which is the hierarchical storage management software. Applications should not arbitrarily change this attribute.
    FILE_ATTRIBUTE_READONLY = 1 #(0x1) A file that is read-only. Applications can read the file, but cannot write to it or delete it. This attribute is not honored on directories. For more information, see You cannot view or change the Read-only or the System attributes of folders in Windows Server 2003, in Windows XP, in Windows Vista or in Windows 7.
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 4194304 #(0x400000) When this attribute is set, it means that the file or directory is not fully present locally. For a file that means that not all of its data is on local storage (e.g. it may be sparse with some data still in remote storage). For a directory it means that some of the directory contents are being virtualized from another location. Reading the file / enumerating the directory will be more expensive than normal, e.g. it will cause at least some of the file/directory content to be fetched from a remote store. Only kernel-mode callers can set this bit.
    FILE_ATTRIBUTE_RECALL_ON_OPEN = 262144 #(0x40000) This attribute only appears in directory enumeration classes (FILE_DIRECTORY_INFORMATION, FILE_BOTH_DIR_INFORMATION, etc.). When this attribute is set, it means that the file or directory has no physical representation on the local system; the item is virtual. Opening the item will be more expensive than normal, e.g. it will cause at least some of it to be fetched from a remote store.
    FILE_ATTRIBUTE_REPARSE_POINT = 1024 #(0x400) A file or directory that has an associated reparse point, or a file that is a symbolic link.
    FILE_ATTRIBUTE_SPARSE_FILE = 512 #(0x200) A file that is a sparse file.
    FILE_ATTRIBUTE_SYSTEM = 4 #(0x4) A file or directory that the operating system uses a part of, or uses exclusively.
    FILE_ATTRIBUTE_TEMPORARY = 256 #(0x100) A file that is being used for temporary storage. File systems avoid writing data back to mass storage if sufficient cache memory is available, because typically, an application deletes a temporary file after the handle is closed. In that scenario, the system can entirely avoid writing the data. Otherwise, the data is written after the handle is closed.
    FILE_ATTRIBUTE_VIRTUAL = 65536 #(0x10000) This value is reserved for system use.

    # for ErrorMode
    SEM_FAILCRITICALERRORS = 0x0001 # The system does not display the critical-error-handler message box. Instead, the system sends the error to the calling process.
    SEM_NOALIGNMENTFAULTEXCEPT = 0x0004 # The system automatically fixes memory alignment faults and makes them invisible to the application. It does this for the calling process and any descendant processes. This feature is only supported by certain processor architectures. For more information, see SetErrorMode.
    SEM_NOGPFAULTERRORBOX = 0x0002  # The system does not display the Windows Error Reporting dialog.
    SEM_NOOPENFILEERRORBOX = 0x8000 # The system does not display a message box when it fails to find a file. Instead, the error is returned to the calling process.


FILE_ATTRIB_DEFAULT = win32const.FILE_ATTRIBUTE_ARCHIVE | win32const.FILE_ATTRIBUTE_NORMAL


#### SYSENTER/SYSCALL helpers
class SystemCallNotImplemented(Exception):
    def __init__(self, callnum, emu, op):
        Exception.__init__(self)
        self.callnum = callnum
        self.emu = emu
        self.op = op

    def __repr__(self):
        return "SystemCall 0x%x (%d) not implemented at 0x%x: %r" % (self.callnum, self.op.va, self.op)

class Kernel(dict):
    def __init__(self, emu, **kwargs):
        dict.__init__(self)
        self.emu = emu
        self.fs_policy = 0  # 7 means allow Read/Write/Execute: see MM_READ
        self.fs_polprompt = True

        self.errno = 0

        # setup key files db here
        self.fs = kwargs.get('fs', collections.defaultdict(dict))    # perhaps create file objects, for now this.
        self.fhandles = kwargs.get('fhandles', {})   # store a connection between a handle and a member of 'fs'
        # File Descriptors
        self.fds = [sys.stdin, sys.stdout, sys.stderr]

    def setFsPolicy(self, fs_policy=0, prompt=True):
        '''
        FileSystem policy indicates what level of permissions this emulator 
        has to read/write/exec in the filesystem.  If fs_policy is loose 
        (eg. MM_READ|MM_WRITE|MM_EXEC), the emulator can read/write/execute 
        without prompting the user.  If the required permissions are not
        allowed (default fs_policy is 0, aka.  nothing), the user is prompted,
        and *no default* is used.  The user must reply with "Y" or "N".  This
        is to ensure you are aware of what impact you are having.

        If you *don't* want to be prompted (some use-cases this makes sense),
        set prompt to False.
        '''
        self.fs_policy = fs_policy
        self.fs_polprompt = prompt

    def registerFd(self, fd):
        # a little hacky, since this will apply a fake filenum to real files
        # but no biggie.  we need some consistency for FakeFiles and real files
        # to coexist in our fake little world here.
        fd._filenum = len(self.fds)     
        self.fds.append(fd)
        return fd._filenum

    def openInternalFile(self, libFileName, mode):
        '''
        '''
        meta = None
        casein = not self.isFsCaseSensitive()
        fullpath = findInternalPath(self, libFileName, casein, matchFnOnly=False)

        try:
            # we have an internal file, ie. one we invented in the TestEmulator.
            meta = self.fs[fullpath]

        except KeyError:
            raise FileNotFoundError(libFileName)

        # file exists and we now have meta
        if meta[0] & win32const.FILE_ATTRIBUTE_NORMAL:
            # found the file.  make and register a FakeFile object
            fakefile = FakeFile(libFileName, meta[1], mode)
            retval = self.registerFd(fakefile)

        else:
            # This is not a normal file.  don't open.
            retval = 0
            raise IsADirectoryError(filename)

        return retval, fakefile

    def openExtFile(self, libFilePath, mode):
        '''
        Return an external file based on filepath mapping.
        libFilePath is a full path

        bytes() not str()
        '''
        if type(mode) == bytes:
            mode = mode.decode('utf8')

        if not 'b' in mode:
            mode = 'b' + mode

        filepath = self.emu.temu.filepath
        print("Attempting to open external file: %r")
        fakepath, realpath = findExtPath(filepath, libFilePath, not self.isFsCaseSensitive(), kernel=self, matchFnOnly=False)
        realfile = open(realpath, mode)
        retval = self.registerFd(realfile)

        # TODO: exception handling?
        return retval, realfile


    def fopen(self, filename, mode):
        '''
        Find the file of interest, check our permissions (TestEmulator and *Kernel 
        should protect users from malicious code)
        '''
        # find file in path
        ## first check files we've defined as strings in the TestEmulator
        retval = None
        try:
            return self.openInternalFile(filename, mode)
            #retval, myfile = self.openInternalFile(filename, mode)
            #return retval, myfile

        except FileNotFoundError:
            # not an internal file... but we need to check the mappings
            pass
        
        ## next check the mapped in filesystem
        # FIXME: in the future: move filepath and all file stuffs into the Kernel
        return self.openExtFile(filename, mode)
        #retval, myfile = self.openExtFile(filename, mode)
        #return retval, myfile


class WinKernel(Kernel):
    sep = b'\\'
    def __init__(self, emu, vermaj=6, vermin=1, arch='i386', syswow=False, **kwargs):
        Kernel.__init__(self, emu, **kwargs)

        if syswow:
            arch = 'wow64'

        self.modbase = 'vstruct.defs.windows.win_%s_%s_%s' % (vermaj, vermin, arch)
        self.win32k = None
        self.ntdll = None
        self.ntoskrnl = None
        self.errormode = win32const.SEM_FAILCRITICALERRORS
        self.last_error = 0
        self.mutexes = {}
        self.dllonexits = {}

        self.freedLibs = collections.defaultdict(dict)

        try:
            self.win32k = __import__(self.modbase + '.win32k', {}, {}, 1)
            self.ntdll = __import__(self.modbase + '.ntdll', {}, {}, 1)
            self.ntoskrnl = __import__(self.modbase + '.ntoskrnl', {}, {}, 1)

            # if we don't have PEB and TEBs as emulator metadata 
            if emu.getMeta('PEB') is None:
                self.teb = self.ntdll.TEB()
                self.peb = self.ntdll.PEB()
                self.initFakePEB(vermaj=vermaj, vermin=vermin, arch=arch)

        except ImportError as e:
            print("error importing VStructs for Windows %d.%d_%s: %r" % (vermaj, vermin, arch, e))
        
        # actual syscall handlers
        self.win_syscalls = {    # worked up on Win7-32
            0xd9: self.sys_win_NtQueryAttributesFile,  # ntdll.ntQueryAttributesFile
            0xdc: self.sys_win_DbgQueryDebugFilterState,  # ntdll.DbgQueryDebugFilterState
            0xb3: self.sys_win_NtOpenFile,
            0x54: self.sys_win_NtCreateSection,
            0xa8: self.sys_win_MapViewOfSection,
            }

    def isFsCaseSensitive(self):
        return False

    def freeLibrary(self, va, libname):
        '''
        '''
        if not self.emu.isValidPointer(va):
            raise Exception("WinKernel.freeLibrary(0x%x, %r) address does not exist in current emulator" % va, libname)

        libdict = self.freedLibs[libname]
        libdict['freed'] = libdict.get('freed', 0) + 1
        libdict['imgbase'] = va

    def loadLibrary(self, va, libname):
        '''
        '''
        libdict = self.freedLibs[libname]
        libdict['load'] = libdict.get('load', 0) + 1

        loadcnt = libdict.get('load')
        freecnt = libdict.get('freed')
        if freecnt:     # if we've already freed this library...
            if loadcnt == freecnt:
                # something is wrong
                print("loadLibrary(0x%x, %r) called and BEEN FREED TOO MANY TIMES (freed: %r load: %r)"\
                        % (va, libname, freecnt, loadcnt))

            elif loadcnt == freecnt+1:
                # this is a reload 
                print("loadLibrary(0x%x, %r) Reload" % (va, libname))
                # should we unload and reload the memory maps?  or just skip emulating the __entry?
                syncEmuWithVw(self.emu.vw, self.emu, name=libname, refresh=True)

        else:   # first time load
            print("loadLibrary(0x%x, %r) loading" % (va, libname))



    def getStackInfo(self):
        stackbase = stacksize = 0
        for mmva, mmsz, mmperm, mmname in self.emu.getMemoryMaps():
            if mmname == '[stack]':
                stackbase = mmva
                stacksize = mmsz
                return stackbase, stacksize

    def initFakePEB(self, vermaj=6, vermin=1, arch=None, pid=0x47145, tid=0x31337):
        '''
        This is currently i386 only
        '''
        if arch is None:
            arch = self.vw.arch.getArchName()

        self.pebbase = self.emu.findFreeMemoryBlock(PEBSZ, 0x7ffd3000)
        self.emu.addMemoryMap(self.pebbase, 6, 'FakePEB', b'\0'*PEBSZ)
        self.tebbase = self.emu.findFreeMemoryBlock(TEBSZ, 0x7ffdc000)
        self.emu.addMemoryMap(self.tebbase, 6, 'FakeTEB', b'\0'*TEBSZ)

        # fake TEB(i386): c4eea6060000a70600e0a60600000000001e0000000000000040fd7f00000000401700000c140000000000002c40fd7f00c0fd7f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000090400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

        # fake PEB(i386): 00000108ffffffff0000e7008088d277b817400000000000000040008083d27700000000000000000100000038d5dc7700000000000000000000eb77000000006082d277ffffffff0700000000006f7f0000000090056f7f0000fb7f2402fc7f4806fd7f01000000000000000000000000809b076de8ffff000010000020000000000100001000000c000000100000000085d27700005d0000000000140000004083d2770600000001000000b11d00010200000003000000060000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

        stackbase, stacksize = self.getStackInfo()

        # populate the TEB/PEB structures
        self.teb.NtTib.Self = self.tebbase
        self.teb.NtTib.StackBase = stackbase + stacksize
        self.teb.NtTib.StackLimit = stackbase
        self.teb.NtTib.FiberData = 0x1e00
        self.teb.CurrentLocale = 0x409

        self.teb.ThreadLocalStoragePointer = self.pebbase + self.teb.vsGetOffset('ThreadLocalStoragePointer')
        self.teb.ProcessEnvironmentBlock = self.pebbase

        self.teb.ClientId.UniqueProcess = pid
        self.teb.ClientId.UniqueThread = tid

        # write everything to emulator memory
        self.emu.writeMemory(self.tebbase, self.teb.vsEmit())
        self.emu.writeMemory(self.pebbase, self.peb.vsEmit())

        if self.emu.psize == 4:
            self.emu.setSegmentInfo(e_i386.SEG_FS, self.tebbase, TEBSZ)
        else:
            self.emu.setSegmentInfo(e_i386.SEG_GS, self.tebbase, TEBSZ)

    def getCurThread(self):
        self.teb.vsParse(self.emu.readMemory(self.tebbase, len(self.teb)))
        return self.teb.ClientId.UniqueThread

    def getCurPid(self):
        self.teb.vsParse(self.emu.readMemory(self.tebbase, len(self.teb)))
        return self.teb.ClientId.UniqueProcess

    def getLastError(self):
        self.teb.vsParse(self.emu.readMemory(self.tebbase, len(self.teb)))
        return self.teb.ClientId.UniqueProcess

    def setLastError(self, last_error):
        self.getLastError()
        self.teb.LastErrorValue = last_error
        self.emu.writeMemory(self.tebbase, self.teb.vsEmit())
        return self.teb.ClientId.UniqueProcess

    def op_sysenter(self, emu, op):
        # handle select Windows syscalls
        callnum = emu.getRegister(0)
        syscall = self.win_syscalls.get(callnum)
        if syscall is not None:
            syscall(emu, op)

        else:
            raise SystemCallNotImplemented(callnum, emu, op)

    def sys_win_DbgQueryDebugFilterState(self, emu, op):
        stackDump(emu)
        sp = emu.getStackCounter()
        arg0 = emu.readMemoryPtr(sp + emu.psize)    # second RET
        arg1 = emu.readMemoryPtr(sp + (2*emu.psize))
        arg2 = emu.readMemoryPtr(sp + (3*emu.psize))

        print("ntDbgQueryDebugFilterState( 0x%x, 0x%x )" % (arg1, arg2))
        # for now
        retval = 0
        emu.setRegister(0, retval)

    def GetTickCount(self):
        '''
        Retrieves the number of milliseconds that have elapsed since the system was started, up to 49.7 days.
        '''
        return int((time.time() - psutil.boot_time()) * 1000) & 0xffffffff

    def GetSystemTime(self):
        '''
        Retrieves the current system date and time. The information is in Coordinated Universal Time (UTC) format.
        '''
        ut = time.localtime()
        return (
                ut[0],
                ut[1],
                ut[6],
                ut[2],
                ut[3],
                ut[4],
                ut[5],
                0x7a69, # how can you resist having 31337 ms???
                )

    def GetSystemTimeAsFileTime(self):
        '''
        Retrieves the current system date and time. The information is in Coordinated Universal Time (UTC) format.
        '''
        return int(self.getWinAbsTime(time.time()))

    def SystemTimeToFileTime(self, systimetup):
        '''
        Retrieves the current system date and time. The information is in Coordinated Universal Time (UTC) format.
        '''
        sometime = self.SystemTimeToUnixFloat(systimetup)

        return int(self.getWinAbsTime(sometime))

    def SystemTimeToUnixFloat(self, systimetup):
        '''
        '''
        unixtup = (
                systimetup[0],
                systimetup[1],
                systimetup[3],
                systimetup[4],
                systimetup[5],
                systimetup[6],
                systimetup[2],
                0,
                -1,
                )
        return time.mktime(unixtup)

    def QueryPerformanceCounter(self):
        '''
        Retrieves the current value of the performance counter, which is a high resolution (<1us) time stamp that can be used for time-interval measurements.
        '''
        return int(time.time() * 1000000)

    def getWinAbsTime(self, ts_since_unix_epoch):
        return (11644473600 + ts_since_unix_epoch) * 10000000

    def getUnixTime(self, ts_since_win_epoch):
        return (ts_since_win_epoch / 10000000) - 11644473600

    def parseUnicodeString(self, emu, addr):
        UNICODE_STRING = self.ntdll.UNICODE_STRING()
        UNICODE_STRING.vsParse(emu.readMemory(addr, len(UNICODE_STRING)))
        return UNICODE_STRING


    def sys_win_NtQueryAttributesFile(self, emu, op):
        stackDump(emu)
        sp = emu.getStackCounter()
        arg0 = emu.readMemoryPtr(sp + emu.psize)
        arg1 = emu.readMemoryPtr(sp + (2*emu.psize))
        arg2 = emu.readMemoryPtr(sp + (3*emu.psize))

        print("ntQueryAttributesFile( 0x%x, 0x%x )" % (arg1, arg2))

        length, rootdir, objname, attrib, secdesc, secqos = \
                emu.readMemoryFormat(arg1, "<IPPIPP")

        if length > 40:
            raise Exception("NtQueryAttributesFile.OBJECT_ATTRIBUTES length: 0x%x (wrong pointer?)" % length)

        fullpathstruct = self.parseUnicodeString(emu, objname)
        fullpath = emu.readMemory(fullpathstruct.Buffer, fullpathstruct.Length)

        if rootdir != 0:
            rootdirstruct = self.parseUnicodeString(emu, rootdir)
            fullpath = emu.readMemory(rootdirstruct.Buffer, rootdirstruct.Length) + fullpath

        print("FullPath: %r" % fullpath)
        # work in ROOTPATH here... right now, just fake
        f = self['fs'][fullpath]
        f['attribmask'] = attrib
        f['secqosptr'] = secqos
        f['secdescptr'] = secdesc
        # need to check the file 

        # FAKE NEWS!
        WriteTime = int(self.getWinAbsTime(time.time()))
        ChangeTime = int(self.getWinAbsTime(time.time()))
        AccessTime = int(self.getWinAbsTime(time.time()))
        CreationTime = int(self.getWinAbsTime(time.time()))
        Attributes = attrib

        print("len:%x rootdir:%x objname:%x attrib:%x secdesc:%x secqos:%x" %(length, rootdir, objname, attrib, secdesc, secqos))
        
        # now we need to write the output data!
        emu.writeMemoryFormat(arg2, '<QQQQI', CreationTime, AccessTime, WriteTime, ChangeTime, Attributes)

        import envi.interactive as ei; ei.dbg_interact(locals(), globals())

        # for now
        retval = 0  # STATUS_SUCCESS
        emu.setRegister(0, retval)

    def sys_win_NtOpenFile(self, emu, op):
        stackDump(emu)
        sp = emu.getStackCounter()
        arg0 = emu.readMemoryPtr(sp + emu.psize)
        arg1 = emu.readMemoryPtr(sp + (2*emu.psize))    # out: FileHandle
        arg2 = emu.readMemoryPtr(sp + (3*emu.psize))    # in: DesiredAccess
        arg3 = emu.readMemoryPtr(sp + (4*emu.psize))    # in: ObjectAttributes
        arg4 = emu.readMemoryPtr(sp + (5*emu.psize))    # out: IoStatusBlock
        arg5 = emu.readMemoryPtr(sp + (6*emu.psize))    # in: ShareAccess
        arg6 = emu.readMemoryPtr(sp + (7*emu.psize))    # in: OpenOptions

        print("ntOpenFile( 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x )" % (arg1, arg2, arg3, arg4, arg5, arg6))
        length, rootdir, objname, attrib, secdesc, secqos = \
                emu.readMemoryFormat(arg3, "<IPPIPP")
        print("  OBJECT_ATTRIBUTES: %r %r %r %r %r %r" % (length, rootdir, objname, attrib, secdesc, secqos))
        import envi.interactive as ei; ei.dbg_interact(locals(), globals())


        # for now
        retval = 0
        emu.setRegister(0, retval)

    def sys_win_NtCreateSection(self, emu, op):
        stackDump(emu)
        ### NOT DONE
        sp = emu.getStackCounter()
        arg0 = emu.readMemoryPtr(sp + emu.psize)
        arg1 = emu.readMemoryPtr(sp + (2*emu.psize))
        arg2 = emu.readMemoryPtr(sp + (3*emu.psize))
        arg3 = emu.readMemoryPtr(sp + (4*emu.psize))
        arg4 = emu.readMemoryPtr(sp + (5*emu.psize))
        arg5 = emu.readMemoryPtr(sp + (6*emu.psize))

        print("ntCreateSection( 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x )" % (arg0, arg1, arg2, arg3, arg4, arg5))
        import envi.interactive as ei; ei.dbg_interact(locals(), globals())

        # for now
        retval = 0
        emu.setRegister(0, retval)

    def sys_win_MapViewOfSection(self, emu, op):
        stackDump(emu)
        ### NOT DONE
        sp = emu.getStackCounter()
        arg0 = emu.readMemoryPtr(sp + emu.psize)
        arg1 = emu.readMemoryPtr(sp + (2*emu.psize))
        arg2 = emu.readMemoryPtr(sp + (3*emu.psize))
        arg3 = emu.readMemoryPtr(sp + (4*emu.psize))
        arg4 = emu.readMemoryPtr(sp + (5*emu.psize))
        arg5 = emu.readMemoryPtr(sp + (6*emu.psize))

        print("ntMapViewOfSection( 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x )" % (arg0, arg1, arg2, arg3, arg4, arg5))
        import envi.interactive as ei; ei.dbg_interact(locals(), globals())

        # for now
        retval = 0
        emu.setRegister(0, retval)

    def _dllonexit(self, va, func, pbegin, pend):
        if va in self.dllonexits:
            print("overwriting dllonexits[0x%x]" % va)

        self.dllonexits[va] = (func, pbegin, pend)

class LinuxKernel(Kernel):
    sep = b'/'
    def __init__(self, emu, **kwargs):
        Kernel.__init__(self, emu, **kwargs)
        
        self.tlsbase = self.emu.findFreeMemoryBlock(TLSSZ, 0x7ffd3000)
        self.emu.addMemoryMap(self.tlsbase, 6, 'FakeTLS', b'\0'*TLSSZ)

        if self.emu.psize == 4:
            self.emu.setSegmentInfo(e_i386.SEG_FS, self.tlsbase, TLSSZ)
        else:
            self.emu.setSegmentInfo(e_i386.SEG_GS, self.tlsbase, TLSSZ)

        # actual syscall handlers
        lin_syscalls = {
        }


    def isFsCaseSensitive(self):
        return True

    def op_sysenter(krnl, emu, op):
        # handle select Linux syscalls
        callnum = emu.getRegister(0)
        syscall = krnl.lin_syscalls.get(callnum)
        if syscall is not None:
            syscall(emu, op)

        else:
            raise SystemCallNotImplemented(callnum, emu, op)




def backTrace(emu):
    '''
    Work through the emulator stack looking for return pointers
    '''
    sp = emu.getStackCounter()
    stackmap = emu.getMemoryMap(sp)
    stacktop = stackmap[0] + stackmap[1]
    while sp < stacktop:
        #print("[D] 0x%x < 0x%x" % (sp, stacktop))
        cur = emu.readMemoryPtr(sp)
        curmap = emu.getMemoryMap(cur)
        if curmap:
            cmmva, cmmsz, cmmperms, cmmname = curmap
            tmpva = max(cur-7, curmap[0])
            tmpsz = cur - tmpva
            prevmem = emu.readMemory(tmpva, tmpsz)

            while tmpva < cur:
                try:
                    op = emu.parseOpcode(tmpva)
                    #print("0x%x: %r" % (op.va, op))
                except:
                    tmpva += 1
                    continue

                if tmpva + len(op) == cur and op.isCall():
                    # this looks like a good call in our call stack
                    tgtfname = 'None'
                    if emu.vw:
                        funcname = emu.vw.getName(emu.vw.getFunction(op.va))
                        tgtvas = [bva for bva, bflags in op.getBranches(emu=emu) if not bflags & envi.BR_FALL]
                        if len(tgtvas) and emu.vw:
                            tgtva = tgtvas[0]
                            tgtfname = emu.vw.getName(tgtva)

                    print("%r   %r   0x%x -> %r" % (cmmname, funcname, op.va, tgtfname))
                tmpva += 1
    
        sp += emu.psize


def stackDump(emu, count=16):
    '''
    Dump Stack, including derefs
    '''
    # TODO: recurse through pointers
    # TODO: list registers that point at any of the pointers/stackaddrs
    print("Stack Dump:")
    sp = emu.getStackCounter()
    for x in range(count):
        val = emu.readMemoryPtr(sp)
        valmap = emu.getMemoryMap(val)
        if valmap and emu.vw:
            bytesleft = (valmap[0] + valmap[1]) - val
            if bytesleft >= emu.psize:
                valptr = emu.readMemoryPtr(val)
                if emu.getMemoryMap(valptr):    # isValidPointer for emus
                    strdata = hex(valptr)
                else:
                    strdata = repr(emu.readMemory(val, min(24, bytesleft)))
            else:
                strdata = repr(emu.readMemory(val, bytesleft))

            print("\t0x%x:\t0x%x \t-> %s" % (sp, val, strdata))
        else:
            print("\t0x%x:\t0x%x" % (sp, val))
        sp += emu.psize

def heapDump(emu):
    '''
    Dump the Heap allocations
    '''
    print("Heap Dump:")
    heap = getHeap(emu)
    print(heap.dump())

import envi
import platform
def getWindowsDef(normname='ntdll', arch='i386', wver='6.1.7601', syswow=False):
    '''
    Get the correct set of Windows VStructs
    '''
    if wver is None:
        bname, wver, stuff, whichkern = platform.win32_ver()
    if arch is None:
        arch = envi.getCurrentArch()

    wvertup = wver.split('.')
    if syswow:
        arch = 'wow64'

    modname = 'vstruct.defs.windows.win_%s_%s_%s.%s' % (wvertup[0], wvertup[1], arch, normname)

    try:
        mod = __import__(modname, {}, {}, 1)
    except ImportError:
        mod = None

    if mod is None:
        modname = 'vstruct.defs.windows.win_%s_%s_%s.%s' % (6, 3, arch, normname)

    try:
        mod = __import__(modname, {}, {}, 1)
    except ImportError:
        mod = None

    return mod

def makeArgs(emu, args=[]):
    '''
    This function takes a list of args and attempts to intelligently convert
    them into something usable with CallingConvention.setupCall().

    The list can be one of a few things:
    * Integers (these are just used straight out, careful on the sizing!)
    * Bytestrings - heap space is carved out and the string copied into it
    * tuple('name', arg) - allows you to set a name for the arg specifically

    In addition to placing the data in the right emulator locations/registers,
    the emulator metadata also holds a copy so you can emulate a function and
    easily see where heap-based arguments were stored for later retrieval.  
    Unnamed args (default) are given the name:
        "Arg%d" % argnum

    str's are utf-encoded to get bytes objects

    *note: only heap-allocations for strings affect the emulator.  Arguments
    are not actually setup for the emulator, this simply adjusts the list
    so the calling convention can work its magic.

    Output is a list appropriate for cconv's setupCall().

    Not perfect, but highly useful.
    '''
    heap = getHeap(emu)
    outargs = []
    for arg in args:
        aname = "Arg%d" % len(outargs)

        if type(arg) in (tuple, list):
            # if we hand in a tuple/list, the first item is the name, second is the arg
            # names are stored in the emulator's metadata
            aname = arg[0]
            arg = arg[1]

        if type(arg) == str:
            # convert strs to bytes
            arg = arg.encode('utf-8')

        if type(arg) == bytes:
            # if it's a bytes (or formerly str), malloc some memory for it
            # use the pointer as the argument
            ptr = heap.malloc(len(arg) + 1)
            emu.writeMemory(ptr, arg)
            outargs.append(ptr)

            emu.setMeta(aname, ptr)

        else:
            outargs.append(arg)
            emu.setMeta(aname, arg)

    return outargs

class TestEmulator:
    def __init__(self, emu, vw=None, verbose=False, fakePEB=False, guiFuncGraphName=None, hookfuncsbyname=False, **kwargs):
        '''
        Instantiate a TestEmulator harness.  This holds and controls an emulator object.

        emu -       an existing emulator
        vw -        VivWorkspace object to build an emulator from
        verbose -   print log messages
        fakePEB -   set up fake PEB/TEB memoryspaces and setup the appropriate segment
        guiFuncGraphName - name of the gui window to send location info to (nav info)
        hookbyname - should we 
        filepath -  path for finding binaries (for emufuncs like LoadLibraryExA), just 
                    like current OS pathing.
        '''
        self.vw = None
        self.vwg = None

        self.emu = emu
        self.emu.temu = self    # i know i'm evil.

        if vw is not None:
            self.vw = emu.vw = vw
            self.vwg = self.vw.getVivGui()
        elif hasattr(emu, 'vw'):
            self.vw = emu.vw
            self.vwg = self.vw.getVivGui()

        self.verbose = verbose
        self.guiFuncGraphName = guiFuncGraphName

        self.XWsnapshot = {}
        self.cached_mem_locs = []
        self.call_handlers = {}
        self.environment = {}
        self.fs = {}
        self.filepath = kwargs.get('filepath', [])
        self.bps = kwargs.get('bps', ())

        self.ctxStack = []
        self.pause = True
        self.nonstop = 0
        self.tova = None
        self.runTil = None
        self.silent = False

        # extFilePath is used for LoadLibrary* type functions, where fs items are inappropriate
        self.extFilePath = ''
        self.nonstop = 0

        self.hookFuncs(importonly = not hookfuncsbyname)

        self.op_handlers = {}   # for instructions like 'sysenter' which are not supported by the emu

        plat = emu.vw.getMeta('Platform')
        if plat.startswith('win'):
            kernel = WinKernel(emu, fs=self.fs, filepath=self.filepath)
        #elif plat.startswith('linux') or plat:
        else:   # FIXME: need to make Elf identification better!!
            kernel = LinuxKernel(emu, fs=self.fs, filepath=self.filepath)

        emu.setMeta('kernel', kernel)
        self.op_handlers['sysenter'] = kernel.op_sysenter


    def storeContext(self):
        '''
        Store nonstop context (not registers or memory, just config) to
        allow call_handlers to call runStep() for "side projects" like 
        LoadLibrary and _initterm to easily run their initialization functions
        '''
        self.ctxStack.append((self.pause, 
            self.nonstop, 
            self.tova, 
            self.silent, 
            self.runTil,
            self.guiFuncGraphName,
            self.bps))

    def restoreContext(self):
        '''
        '''
        (self.pause,
                self.nonstop,
                self.tova,
                self.silent,
                self.runTil,
                self.guiFuncGraphName,
                self.bps) = self.ctxStack.pop()

    def getKernel(self):
        '''
        Returns the Kernel object registered in the Emulator metadata
        '''
        return self.emu.getMeta('kernel')

    def setFileInfo(self, filename, filebytes, fileattrib=0):
        '''
        Add/Replace Filesystem data
        filedict is a dictionary of attributes/timestamps
        '''
        self.fs[filename] = (fileattrib, filebytes)

    def addCallHandler(self, addrexpr, handler):
        '''
        Add callback handlers to the TestEmulator.  
        Instead of handing in addresses, hand in expressions for a more dynamic
        lookup (say, you want to use the same tools between different workspace
        with different file load locations!
        '''
        if type(addrexpr) in (str, bytes):
            addrexpr = self.vw.parseExpression(addrexpr)

        if self.vw.isValidPointer(addrexpr):
            self.call_handlers[addrexpr] = handler

    def hookFuncs(self, importonly=True):
        '''
        Automagically setup call-hooks for external functions we know about.

        The end result is that the TestEmulator's call_handlers dictionary 
        is automatically populated based on function names and the mapping
        done by import_map.

        Requires that TestEmulator has access to a VivWorkspace.  Either:
        * self.vw
        * self.emu.vw
        '''
        if not hasattr(self.emu, 'vw') or self.emu.vw is None:
            return

        for impva, impsz, imptype, impname in self.emu.vw.getImports():
            fname, funcname = impname.split('.', 1)
            if impname in import_map:
                self.call_handlers[impva] = import_map.get(impname)
            elif "*." + funcname in import_map:
                impname = "*." + funcname
                self.call_handlers[impva] = import_map.get(impname)

        if importonly:
            return

        for va, name in self.emu.vw.getNames():
            #print(name, '%.8x' % va)
            if name.endswith("%.8x" % va):
                name = name[:-9]
                #print("checking %r" % name)


            if name in import_map:
                self.call_handlers[va] = import_map.get(name)
                print("Mapping call_handler by *name*: %r => 0x%x" % (name, va))

    def setupCall(self, fva, ezargs=[], retaddr=0x47145, ccname=None):
        '''
        Easily setup an emulator to call into a function.

        Args are setup (see docstring for makeArgs()), space allocated (if 
        necessary) for Return Address, and return address setup, then the
        Program Counter is pointed at the function you wish to call.

        In the end, it's as if the call already happened.

        This function is highly dependent upon correct Calling Convention
        being identified by Vivisect, or the ccname being handed into this
        function.
        '''
        emu = self.emu

        # convert from ezargs to all pointers
        args = makeArgs(emu, ezargs)

        if type(fva) == str:
            fva = emu.vw.parseExpression(fva)

        # use the ccname if provided, or figure it out from the Workspace
        if ccname is None:
            api = emu.getCallApi(fva)
            ccname = api[2]

        cconv = emu.getCallingConvention(ccname)
        cconv.setupCall(emu, args=args, ra=retaddr)
        emu.setProgramCounter(fva)

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
        if type(reggrps) == list:
            for name, gen_regs in reggrps:
                if name == 'general':
                    break
        elif type(reggrps) == dict:
            gen_regs = reggrps.get('general')

        reg_table, meta_regs, PC_idx, SP_idx, reg_vals = emu.getRegisterInfo()
        if isinstance(emu, vtrace.Trace):
            reg_table, meta_regs, PC_idx, SP_idx, reg_vals = emu.getRegisterContext().getRegisterInfo()
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

    def showFlags(self, maxflags=20):
        """
        Show the contents of the Status Register
        """
        #print("\tStatus Flags: \tRegister: %s\n" % (bin(self.getStatusRegister())))
        try:
            flags = self.emu.getStatusFlags().items()
            if len(flags) > maxflags:
                flags = list(flags)[:maxflags]
            print("StatFlags: " + '\t'.join(["%s %s" % (f,v) for f,v in flags]))
        except Exception as e:
            print("no flags: ", e)


    def backTrace(self):
        emu = self.emu
        backTrace(emu)

    def stackDump(self, count=16):
        # TODO: recurse through pointers
        # TODO: list registers that point at any of the pointers/stackaddrs
        emu = self.emu
        stackDump(emu, count)

    def heapDump(self):
        emu = self.emu
        heapDump(emu)

    def printStats(self, i):
        curtime = time.time()
        dtime = curtime - self.startRun
        print("since start: %d instructions in %.3f secs: %3f ops/sec" % \
                (i, dtime, i//dtime))

    def resetNonstop(self):
        '''
        Reset pause, nonstop, and tova
        '''
        self.pause = True
        self.nonstop = 0
        self.tova = None

    def runStep(self, maxstep=1000000, follow=True, showafter=True, runTil=None, pause=True, silent=False, finish=0, tracedict=None, bps=()):
        '''
        runStep is the core "debugging" functionality for this emulation-helper.  it's goal is to 
        provide a single-step interface somewhat like what you might get from a GDB experience.  

        pertinent registers are printed with their values, the current instruction, and any helpers
        that the operands may point to in memory (as appropriate).

        special features:
        [ function arguments ]
        * tracedict allows code to be evaluated and printed at specific addresses: 
                tracedict={va:'python code here', 'locals':{'something':4}}

        * call_handlers dict (global in the library) allows swapping in our python code in place of 
            calls to other binary code, like memcpy, or other code which may fail in an emulator

        * follow - should the emulator follow calls?

        * showafter - show memory and operands *after* emulating the instruction

        * runTil - duplication of "finish" - will be removed in the future
        
        * pause - do we stop at each instruction?
        
        * silent - do we print out status after each instruction?
        
        * finish - when the Program Counter reaches this address, stop
        
        [ interactive cli ]
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
        
        '''
        self.storeContext()

        emu = self.emu
        self._follow = follow
        self.pause = pause
        self.silent = silent
        mcanv = e_memcanvas.StringMemoryCanvas(emu, syms=emu.vw)
        self.mcanv = mcanv  # store it for later inspection

        # set up tracedict
        if tracedict is None:
            tracedict = {}
        else:
            print("tracedict entries for %r" % (','.join([hex(key) for key in tracedict.keys() if type(key) == int])))


        # if we provide new breakpoints, use them instead.  this is dangerous.  maybe not make these fields, but local tuple?
        if bps:
            self.bps = bps

        self.nonstop = 0
        self.tova = None
        self.quit = False
        self.moveon = False
        self.emuBranch = False
        self.silentUntil = None

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
                    if not self.silent:
                        print("PC reached 0x%x." % pc)
                    break

                if pc in self.bps:
                    self.resetNonstop()

                op = emu.parseOpcode(pc)
                self.op = op    # store it for later in case of post-mortem
                #print("0x%x" % op.va)
                op.va = pc # handle wild-ass bug i ran into in the wild?!?  caching bug?

                # cancel self.emuBranch as we've come to one
                if op.isReturn() or op.isCall():
                    self.emuBranch = False

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

                if self.silentUntil == pc:
                    self.silent = False
                    self.silentUntil = None
                    self.printStats(i)

                if self.silent and not pc in silentExcept:
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

                    # self.nonstop controls whether we stop.  self.tova indicates we're hunting for a va, otherwise 
                    # treat self.nonstop as a negative-counter
                    if self.tova is not None:
                        if pc == self.tova:
                            self.nonstop = 0

                    elif self.nonstop:
                        self.nonstop -= 1

                    if not (self.emuBranch or self.nonstop) and self.pause:
                        self.tova = None
                        nextva = op.va + len(op)
                        self.moveon = False

                        # send the selected GUI window to current program counter
                        if self.guiFuncGraphName is not None and not self.silent:
                            if self.vwg is not None:
                                self.vwg.sendFuncGraphTo(pc, self.guiFuncGraphName)
                            else:
                                print("can't send FuncGraph to 0x%x because we don't have a handle to the Viv GUI" % pc)

                        # UI Interface!  interact with the user
                        uinp = input(prompt)
                        while len(uinp) and not (self.moveon or self.quit or self.emuBranch):
                            try:
                                if uinp == "q":
                                    self.quit = True
                                    break

                                elif uinp.startswith('silent'):
                                    parts = uinp.split(' ')
                                    self.silentUntil = parseExpression(emu, parts[-1], {'next':nextva})
                                    print("silent until 0x%x" % self.silentUntil)
                                    self.silent = True

                                elif uinp in ('backtrace', 'bt'):
                                    self.backTrace()
                                    self.moveon = True
                                    break

                                elif uinp.startswith('go '):
                                    args = uinp.split(' ')

                                    if args[-1].startswith('+'):
                                        self.nonstop = parseExpression(emu, args[-1], {'next': nextva})
                                    else:
                                        self.tova = parseExpression(emu, args[-1], {'next': nextva})
                                        self.nonstop = 1
                                    break

                                elif uinp == 'ni':
                                    # next instruction (eg. skip over a call)
                                    self.nonstop = 1
                                    self.tova = nextva
                                    break

                                elif uinp in ('b', 'branch'):
                                    self.emuBranch = True
                                    break

                                elif uinp.startswith('stack'):
                                    count=16
                                    if ' ' in uinp:
                                        cmd, ctstr = uinp.split(' ', 1)
                                        try:
                                            count = int(ctstr, 0)
                                        except ValueError as e:
                                            print(e)

                                    self.stackDump(count)
                                    self.moveon = True
                                    break

                                elif uinp == 'heap':
                                    self.heapDump()
                                    self.moveon = True
                                    break

                                elif uinp.startswith('malloc'):
                                    self.moveon = True
                                    size = 32

                                    if ' ' in uinp:
                                        parts = uinp.split(' ', 1)
                                        try:
                                            size = parseExpression(emu, parts[1], {})
                                        except Exception as e:
                                            print("ERROR with size, using default 32bytes : %r" % e)

                                    heap = getHeap(emu)
                                    chunk = heap.malloc(size)
                                    print("MALLOC:  New chunk:  0x%x" % chunk)

                                    break

                                elif uinp == 'refresh':
                                    # basically does a NOP, doesn't change anything, just let the data be reprinted.
                                    self.moveon = True
                                    break

                                elif uinp.startswith('pc=') or uinp.startswith('pc ='):
                                    print("handling setProgramCounter()")
                                    args = uinp.split('=')
                                    newpc = parseExpression(emu, args[-1])
                                    print("new PC: 0x%x" % newpc)
                                    emu.setProgramCounter(newpc)
                                    self.moveon = True
                                    break

                                elif '=' in uinp:
                                    print("handling generic register/memory writes")
                                    args = uinp.split('=')
                                    data = args[-1].strip() #   .split(',')  ??? why did i ever do this?

                                    if '[' in args[0]:
                                        # memory derefs
                                        tgt = args[0].replace('[','').replace(']','').split(':')
                                        addrstr = tgt[0]
                                        memaddr = parseExpression(emu, addrstr)

                                        if len(tgt) > 1:
                                            if tgt[-1] not in ('h', 'H', 's', 'S'):
                                                size = parseExpression(emu, tgt[-1])
                                        else:
                                            size = emu.psize


                                        if data.startswith('"') and data.endswith('"'):
                                            # write string data
                                            bdata = (data[1:-1]).encode()
                                            emu.writeMemory(memaddr, bdata)
                                        elif tgt[-1] in ('h', 'H'):
                                            bdata = bytes.fromhex(data.encode())
                                            emu.writeMemory(memaddr, bdata)
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
                                            nexpr, nsize = expr.rsplit(':',1)
                                            va = parseExpression(emu, nexpr)
                                            if nsize in ('s', 'S'):
                                                data = emu.readMemString(va)
                                                print("[%s] == %r" % (expr, data))
                                            elif nsize in ('w', 'W'):
                                                data = readMemString(emu, va, wide=True)
                                                print("[%s] == %r" % (expr, data))
                                            elif nsize in ('u', 'U'):
                                                data = readMemString(emu, va, wide=True)
                                                print("[%s] == %r" % (expr, data.decode('utf-16le')))
                                            else:
                                                try:
                                                    size = parseExpression(emu, nsize)
                                                    data = emu.readMemory(va, size)
                                                    print("[%s:%s] == %r" % (nexpr, size, data.hex()))
                                                except Exception as e:
                                                    # if number fails, just continue with a default size and the original expr
                                                    print("unknown size: %r.  using default size." % size)

                                        else:
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

                                else:
                                    try:
                                        lcls = {'next': nextva}
                                        lcls.update(locals())
                                        lcls.update(emu.getRegisters())
                                        if isinstance(emu, vtrace.Trace):
                                            lcls.update(emu.getRegisterContext().getRegisters())

                                        out = eval(uinp, globals(), lcls)

                                        if type(out) == int:
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

                if self.quit:
                    print("Quitting!")
                    self.printStats(i)
                    self.restoreContext()
                    return

                if self.moveon:
                    continue

                if op.isCall() or op.iflags & envi.IF_BRANCH:
                    skip, skipop = self.handleBranch(op, skip, skipop)

                # if not already emulated a call, execute the instruction here...
                if not skip and not skipop:
                    # execute opcode.  if unsupported, look for op_handlers
                    failed = False
                    try:
                        emu.stepi()
                    except e_exc.UnsupportedInstruction:
                        failed = True
                    except e_exc.BreakpointHit:
                        print("Breakpoint Hit!")
                        failed = True

                    # check for failure, and look for an op_handler. then raise an exception
                    if failed:
                        ophndlr = self.op_handlers.get(op.mnem)

                        if ophndlr is not None:
                            print("opcode handler: %r" % ophndlr)
                            newpc = ophndlr(emu, op)
                            if not newpc:
                                newpc = op.va + len(op)

                            emu.setProgramCounter(newpc)

                        else:
                            import sys
                            sys.excepthook(*sys.exc_info())
                            break


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
                self.nonstop = 0
                self.pause = True
                break

            except envi.SegmentationViolation:
                pc = emu.getProgramCounter()
                taint = emu.getVivTaint(pc)
                if op.isCall() or op.iflags & envi.IF_BRANCH and taint:
                    skip, skipop = self.handleBranch(op, skip, skipop)
                else:
                    import sys
                    sys.excepthook(*sys.exc_info())
                    break

            except:
                self.nonstop = 0
                self.pause = True
                import sys
                sys.excepthook(*sys.exc_info())

        if not self.silent:
            self.printStats(i)
        self.restoreContext()

    def handleBranch(self, op, skip, skipop):
        '''
        '''
        emu = self.emu
        handler = None
        for brva, brflags in op.getBranches(emu=emu):
            if brflags & envi.BR_FALL:
                continue

            if hasattr(emu, 'getVivTaint'):
                taint = emu.getVivTaint(brva)
                if taint:
                    taintval, tainttype, tainttuple = taint
                    brva = tainttuple[0]

            self.dbgprint("brva: 0x%x  brflags: 0x%x" % (brva, brflags))
            handler = self.call_handlers.get(brva)
            if handler is not None:
                break

        self.dbgprint( " handler for call to (0x%x): %r" % (brva, handler))
        if handler is not None:
            if op.isCall():
                # apply return address. any supported arch callconv should
                # get this right... so take the first one.
                retva = op.va + len(op)
                ccname, cconv = emu.getCallingConventions()[0]
                cconv.allocateReturnAddress(emu)    # this assumes we've called
                cconv.setReturnAddress(emu, retva)
                print("\n%r:  setting return address to 0x%x" % (handler, retva))

            handler(emu, op)
            skip = True
            if not op.isCall():
                # this was a branch... our handlers are intended to handle calls.
                print("handleBranch(): have handler, but %r (at 0x%x) is not a call, may work fine, but may not." % (op, op.va))


        elif self._follow and not skip and not skipop:
            # use the emulator to execute the call
            starteip = emu.getProgramCounter()
            if hasattr(emu, 'emumon') and emu.emumon is not None:
                emu.emumon.prehook(emu, op, starteip)

            emu.executeOpcode(op)
            endeip = emu.getProgramCounter()
            if hasattr(emu, 'emumon') and emu.emumon is not None:
                emu.emumon.posthook(emu, op, endeip)

            self.dbgprint("starteip: 0x%x, endeip: 0x%x  -> %s" % (starteip, endeip, emu.vw.getName(endeip)))
            if hasattr(emu, 'curpath'):
                vg_path.getNodeProp(emu.curpath, 'valist').append(starteip)
            skip = True

        return skip, skipop

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
        self.runStep()

    def printWriteLog(self):
        print('\n'.join(['0x%.8x: 0x%.8x << %32r %r' % (x,y,d.hex(),d) for x,y,d in self.emu.path[2].get('writelog')]))


    def insertReadWriteComments(self, vw):
        for va, tva, data in self.emu.path[2].get('readlog'):
            insertComment(vw, va, "[r:%x] %r (%r)" % (tva, data.hex(), data))

        for va, tva, data in self.emu.path[2].get('writelog'):
            insertComment(vw, va, "[W:%x] %r (%r)" % (tva, data.hex(), data))

def readMemString(self, va, maxlen=0xfffffff, wide=False):
    '''
    Returns a C-style string from memory.  Stops at Memory Map boundaries, or the first NULL (\x00) byte.
    '''

    if wide:
        term = b'\0\0'
    else:
        term = b'\0'

    for mva, mmaxva, mmap, mbytes in self._map_defs:
        if mva <= va < mmaxva:
            mva, msize, mperms, mfname = mmap
            if not mperms & MM_READ:
                raise envi.SegmentationViolation(va)
            offset = va - mva

            # now find the end of the string based on either \x00, maxlen, or end of map
            end = mbytes.find(term, offset)

            left = end - offset
            if end == -1:
                # couldn't find the NULL byte
                mend = offset + maxlen
                cstr = mbytes[offset:mend]
            else:
                # couldn't find the NULL byte go to the end of the map or maxlen
                if wide and (left & 1):
                    left += 1
                mend = offset + (maxlen, left)[left < maxlen]
                cstr = mbytes[offset:mend]
            return cstr

    raise envi.SegmentationViolation(va)



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


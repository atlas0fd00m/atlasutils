#!/usr/bin/env python
import os
import cmd
import sys
import time
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
STRUNCATE = 80

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
        data1 += '\0'
        data2 += '\0'

    for idx in min(data1len, data2len):
        if data1[idx] != data2[idx]:
            failed = True
            break
    
    retval = data2[idx] - data1[idx]
    if failed:
        print("strcmp failed: %d" % retval)

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


#### Win32 helper functions
def Sleep(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    dwMS = cconv.getCallArgs(emu, 1)
    print("Sleep: dwMillisectonds: %d" % (dwMS))
    # calling getHeap initializes a heap.  we can cheat for now.  we may need to initialize new heaps here
    time.sleep(dwMS/1000)
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


def GetLastError(emu, op=None):
    kernel = emu.getMeta('kernel')
    ccname, cconv = getMSCallConv(emu, op.va)
    cconv.execCallReturn(emu, kernel.last_error, 0)

def SetLastError(emu, op=None):
    kernel = emu.getMeta('kernel')
    ccname, cconv = getMSCallConv(emu, op.va)
    kernel.last_error, = cconv.getCallArgs(emu, 1)
    cconv.execCallReturn(emu, 0, 1)

def GetCurrentThreadId(emu, op=None):
    kernel = emu.getMeta('kernel')
    ccname, cconv = getMSCallConv(emu, op.va)
    cconv.execCallReturn(emu, kernel.curthread, 0)

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

def findPath(filepath, libFileName, casein=False):
    '''
    helper function to dig through paths and find a file

    filepath is a list of directories
    libFileName is a filename we're looking for
    casesensitive
    '''
    if casein:
        libFileName = libFileName.upper()

    for pathpart in filepath:
        for fname in os.listdir(pathpart):
            f = fname
            if casein:
                f = f.upper()

            if f == libFileName:
                return(os.sep.encode('utf-8').join([pathpart, fname]))


def FreeLibrary(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    hLibModule, = cconv.getCallArgs(emu, 1)
    fname = emu.vw.getFileByVa(hLibModule)

    print("FreeLibrary(0x%x)  (%r)" % (hLibModule, fname))
    # Yeah, we don't *gotta* do nothin... and ain't *gonna* do nothin

    cconv.execCallReturn(emu, hLibModule, 1)


def LoadLibraryExA(emu, op=None):
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
    
    # get the name as it would appear in Viv's memory maps:
    normfn = emu.vw.normFileName(libFileName.decode('utf-8'))

    # go until it's loaded or we tell it to bugger off.
    while result is None:
        try:
            result = emu.vw.parseExpression(normfn)
            print("Map loaded...")

            break

        except ExpressionFail as e:
            print(e)
            # if we don't have it already loaded and resolvable in the workspace
            # we must load it
           
            try:
                # TODO: take a path and go hunting for the dll in the path
                filepath = findPath(emu.temu.filepath, libFileName)
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

                # merge the imported memory maps from the Workspace into the emu
                print("Sync VW maps to EMU...")
                syncEmuWithVw(emu.vw, emu)
                print("Synced")
            except Exception as e:
                print("Error while attempting to load %r:  %r" % (normfn, e))

        except KeyboardInterrupt:
            break

        except Exception as e:
            print(e)

    cconv.execCallReturn(emu, result, 3)


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
    ccname, cconv = getMSCallConv(emu, op.va)
    hModule, lpFilename, nSize = cconv.getCallArgs(emu, 3)

    filename = emu.vw.getFileByVa(hModule).encode('utf-8')
    filename += b'.dll'
    print("GetModuleFileNameA(%r)" % filename)

    ## do we want this?
    #filepath = findPath(emu.temu.filepath, filename, casein=True)
    #print("GetModuleFileNameA() -> %r" % filepath)

    #### CHEAT!
    filename = b"C:\\Windows\\System32\\" + filename

    if len(filename) >= nSize:
        filename = filename[:nSize-1]
    filename += b'\0'    # warning: WinXP doesn't mandate the '\0'

    emu.writeMemory(lpFilename, filename)
    result = len(filename) -1   # don't include the terminating null

    cconv.execCallReturn(emu, result, 3)

def CreateMutexA(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    lpMutexAttributes, bInitialOwner, lpName = cconv.getCallArgs(emu, 3)
    name = b''

    # this is a rough skelleton for hacking purposes...
    heap = getHeap(emu)
    mutex = heap.malloc(16) # guess at some size

    mutexes = emu.getMeta('Mutexes')
    if mutexes is None:
        mutexes = {}
        emu.setMeta('Mutexes', mutexes)

    if lpName:
        name = emu.readMemString(lpName)

    mutexes[mutex] = (name, bInitialOwner, lpMutexAttributes)
    print("CreateMutexA: (0x%x, %r, 0x%x, 0x%x)" % (mutex, name, bInitialOwner, lpMutexAttributes))

    cconv.execCallReturn(emu, mutex, 3)

def ReleaseMutex(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    hMutex, = cconv.getCallArgs(emu, 1)

    # hack: assume current thread owns the mutex.  don't return errors
    mutexes = emu.getMeta('Mutexes')
    mutup = mutexes.get(hMutex)
    print("ReleaseMutex(0x%x): %r" % (hMutex, mutup))

    # for historical purposes, leave it alone

    cconv.execCallReturn(emu, hMutex, 1)

def WaitForSingleObject(emu, op=None):
    ccname, cconv = getMSCallConv(emu, op.va)
    hHandle, dwMilliseconds = cconv.getCallArgs(emu, 2)

    WAIT_ABANDONED = 0x00000080
    WAIT_OBJECT_0 = 0x00000000
    WAIT_TIMEOUT = 0x00000102
    WAIT_FAILED = 0xFFFFFFFF

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

def syncEmuWithVw(vw, emu):
    for mmva, mmsz, mmperm, mmname in vw.getMemoryMaps():
        if emu.isValidPointer(mmva):
            continue

        # not a valid pointer in the emu, add the map
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
    count = string.count('%')
    neg2 = string.count('%%')
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

import_map = {
        '*.syslog': syslog,
        '*.malloc': malloc,
        '*.calloc': calloc,
        '*.free': free,
        '*.realloc': realloc,
        '*.strlen': strlen,
        '*.strcmp': strcmp,
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
        'kernel32.GetLastError': GetLastError,
        'kernel32.SetLastError': SetLastError,
        'kernel32.TlsAlloc': TlsAlloc,
        'kernel32.TlsGetValue': TlsGetValue,
        'kernel32.TlsSetValue': TlsSetValue,
        'kernel32.GetCurrentThreadId': GetCurrentThreadId,
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
        'ntdll._vsnprintf': vsnprintf,
        'msvcr100.getenv_s': getenv_s,
        'msvcr100.calloc': calloc,
        'msvcr100.strncpy_s': strncpy_s,
        'msvcr100.strncat_s': strncat_s,
        'msvcr100.strtok_s': strtok_s,
        'msvcr100.strrchr': strrchr,
        'msvcr100.free': free,
        'msvcr100._strdup': strdup,
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

#### SYSENTER/SYSCALL helpers
class SystemCallNotImplemented(Exception):
    def __init__(self, callnum, emu, op):
        Exception.__init__(self)
        self.callnum = callnum
        self.emu = emu
        self.op = op

    def __repr__(self):
        return "SystemCall 0x%x (%d) not implemented at 0x%x: %r" % (self.callnum, self.op.va, self.op)

class WinKernel(dict):
    def __init__(self, emu, vermaj=6, vermin=1, arch='i386', syswow=False):
        dict.__init__(self)
        self.emu = emu

        if syswow:
            arch = 'wow64'

        self.modbase = 'vstruct.defs.windows.win_%s_%s_%s' % (vermaj, vermin, arch)
        self.win32k = None
        self.ntdll = None
        self.ntoskrnl = None
        self.errormode = win32const.SEM_FAILCRITICALERRORS
        self.curthread = 0x31337
        self.last_error = 0
        try:
            self.win32k = __import__(self.modbase + '.win32k', {}, {}, 1)
            self.ntdll = __import__(self.modbase + '.ntdll', {}, {}, 1)
            self.ntoskrnl = __import__(self.modbase + '.ntoskrnl', {}, {}, 1)
        except ImportError as e:
            print("error importing VStructs for Windows %d.%d_%s: %r" % (vermaj, vermin, arch, e))
        
        # setup key files db here
        self['fs'] = collections.defaultdict(dict)    # perhaps create file objects, for now this.
        self['fhandles'] = {}   # store a connection between a handle and a member of 'fs'

        # actual syscall handlers
        self.win_syscalls = {    # worked up on Win7-32
            0xd9: self.sys_win_NtQueryAttributesFile,  # ntdll.ntQueryAttributesFile
            0xdc: self.sys_win_DbgQueryDebugFilterState,  # ntdll.DbgQueryDebugFilterState
            0xb3: self.sys_win_NtOpenFile,
            0x54: self.sys_win_NtCreateSection,
            0xa8: self.sys_win_MapViewOfSection,
            }


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


class LinuxKernel(dict):
    def __init__(self, emu):
        dict.__init__(self)
        self.emu = emu

        
        # setup key files db here
        self['fs'] = collections.defaultdict(dict)    # perhaps create file objects, for now this.
        self['fhandles'] = {}   # store a connection between a handle and a member of 'fs'

        # actual syscall handlers
        win_syscalls = {
            }


    def op_sysenter(krnl, emu, op):
        # handle select Windows syscalls
        callnum = emu.getRegister(0)
        syscall = krnl.win_syscalls.get(callnum)
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
    print("Stack Dump:")
    heap = getHeap(emu)
    print(heap.dump())

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

        # extFilePath is used for LoadLibrary* type functions, where fs items are inappropriate
        self.extFilePath = ''

        self.hookFuncs(importonly = not hookfuncsbyname)

        self.teb = None
        self.peb = None
        if fakePEB:
            self.initFakePEB()

    def setFileInfo(self, filename, filebytes, fileattrib=0):
        '''
        Add/Replace Filesystem data
        filedict is a dictionary of attributes/timestamps
        '''
        self.fs[filename] = (fileattrib, filebytes)

    def initFakePEB(self):
        '''
        This is currently i386 only
        '''
        peb = self.emu.findFreeMemoryBlock(PEBSZ, 0x7ffd3000)
        self.emu.addMemoryMap(peb, 6, 'FakePEB', b'\0'*PEBSZ)
        teb = self.emu.findFreeMemoryBlock(TEBSZ, 0x7ffdc000)
        self.emu.addMemoryMap(teb, 6, 'FakeTEB', b'\0'*TEBSZ)

        self.emu.writeMemoryPtr(teb+0x30, peb)
        # fake TEB: c4eea6060000a70600e0a60600000000001e0000000000000040fd7f00000000401700000c140000000000002c40fd7f00c0fd7f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000090400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

        # fake PEB: 00000108ffffffff0000e7008088d277b817400000000000000040008083d27700000000000000000100000038d5dc7700000000000000000000eb77000000006082d277ffffffff0700000000006f7f0000000090056f7f0000fb7f2402fc7f4806fd7f01000000000000000000000000809b076de8ffff000010000020000000000100001000000c000000100000000085d27700005d0000000000140000004083d2770600000001000000b11d00010200000003000000060000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

        if self.emu.psize == 4:
            self.emu.setSegmentInfo(e_i386.SEG_FS, teb, TEBSZ)
        else:
            self.emu.setSegmentInfo(e_i386.SEG_GS, teb, TEBSZ)


    def hookFuncs(self, importonly=True):
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

    def showFlags(self):
        """
        Show the contents of the Status Register
        """
        #print("\tStatus Flags: \tRegister: %s\n" % (bin(self.getStatusRegister())))
        try:
            print("\tStatFlags: " + '\t'.join(["%s %s" % (f,v) for f,v in self.emu.getStatusFlags().items()]))
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

    def runStep(self, maxstep=1000000, follow=True, showafter=True, runTil=None, pause=True, silent=False, finish=0, tracedict=None):
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
        emu = self.emu
        self._follow = follow
        self.op_handlers = {}   # for instructions like 'sysenter' which are not supported by the emu

        plat = emu.vw.getMeta('Platform')
        if plat.startswith('win'):
            kernel = WinKernel(emu)
        #elif plat.startswith('linux') or plat:
        else:   # FIXME: need to make Elf identification better!!
            kernel = LinuxKernel(emu)

        emu.setMeta('kernel', kernel)
        self.op_handlers['sysenter'] = kernel.op_sysenter

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
                                self.vwg.sendFuncGraphTo(pc, self.guiFuncGraphName)
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

                                elif uinp in ('backtrace', 'bt'):
                                    self.backTrace()
                                    moveon = True
                                    break

                                elif uinp.startswith('go '):
                                    args = uinp.split(' ')

                                    if args[-1].startswith('+'):
                                        nonstop = parseExpression(emu, args[-1], {'next': nextva})
                                    else:
                                        tova = parseExpression(emu, args[-1], {'next': nextva})
                                        nonstop = 1
                                    break

                                elif uinp == 'ni':
                                    # next instruction (eg. skip over a call)
                                    nonstop = 1
                                    tova = nextva
                                    break

                                elif uinp in ('b', 'branch'):
                                    emuBranch = True
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
                                    moveon = True
                                    break

                                elif uinp == 'heap':
                                    self.heapDump()
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

                                # the following functions are DEPRECATED
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
                                        if isinstance(emu, vtrace.Trace):
                                            lcls.update(emu.getRegisterContext().getRegisters())

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
                '''
                # handle Calls separately
                if op.isCall() and not skipop:
                    self.dbgprint("Call...")
                    handler = None
                    for brva, brflags in op.getBranches(emu=emu):
                        if brflags & envi.BR_FALL:
                            continue

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
                        handler(emu, op)
                        skipop = True

                    elif self._follow and not skip and not skipop:
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
                '''
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
                import sys
                sys.excepthook(*sys.exc_info())
                nonstop = 0

        self.printStats(i)

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
        runStep(emu)

    def printWriteLog(self):
        print('\n'.join(['0x%.8x: 0x%.8x << %32r %r' % (x,y,d.hex(),d) for x,y,d in self.emu.path[2].get('writelog')]))


    def insertReadWriteComments(self, vw):
        for va, tva, data in self.emu.path[2].get('readlog'):
            insertComment(vw, va, "[r:%x] %r (%r)" % (tva, data.hex(), data))

        for va, tva, data in self.emu.path[2].get('writelog'):
            insertComment(vw, va, "[W:%x] %r (%r)" % (tva, data.hex(), data))

from envi.memory import MM_READ
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


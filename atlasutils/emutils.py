#!/usr/bin/env python
import cmd
import sys
import struct
# from ihexparser import *
import struct
import envi
import envi.memory as e_m
import envi.expression as e_expr
import envi.memcanvas as e_memcanvas

import atlasutils.smartprint as sp
import visgraph.pathcore as vg_path

IRAM_SIZE = 0x30
IRAM_OFFSET = 0
FLASH_OFFSET = 0

cached_mem_locs = []


def printMemStatus(emu, op=None, use_cached=False):
    global cached_mem_locs
    pc = emu.getProgramCounter()
    SP = emu.getStackCounter()
    if op is None:
        return

    done = []
    if use_cached:
        addrs = cached_mem_locs
    else:
        addrs = []
        for oper in op.opers:
            try:
                # value
                addr = oper.getOperValue(op, emu)
                if type(addr) in (int, long):
                    if addr not in addrs:
                        addrs.append(addr)
                # address
                addr = oper.getOperAddr(op, emu)
                if addr is not None:
                    if addr not in addrs:
                        addrs.append(addr)
            except Exception as e:
                print "error: %s" % e

    for addr in addrs:
        if not emu.isValidPointer(addr):
            if emu.vw.verbose:
                if type(addr) in (int, long):
                    print "No valid memory at address: 0x%x" % addr
                else:
                    print "No valid memory at address: %s" % addr
            continue
        print XW(emu, addr, snapshot=SNAP_SWAP)
    cached_mem_locs = addrs


SNAP_NORM = 0
SNAP_CAP = 1
SNAP_DIFF = 2
SNAP_SWAP = 3
XWsnapshot = {}


def XW(tracer, address, length=3, dwperline=8, snapshot=0):
    global XWsnapshot

    output = []
    mm = tracer.getMemoryMap(address)
    if mm is None:
        return ''

    mmva, mmsz, mmperm, mmname = mm
    if mmva+mmsz < address + (length*4):
        goodbcnt = (mmva+mmsz-address)
        diff = (length*4) - goodbcnt
        bs = tracer.readMemory(address, goodbcnt)
        bs += 'A' * diff

    else:
        bs = tracer.readMemory(address, length*4)

    for i in range(length):
        addr = address + (i * 4)
        if (i % dwperline == 0):
            output.append("%.08x:\t " % (addr))

        data = bs[i*4:(i*4)+4]

        # do the snapshotting thing
        pre = post = ''
        if snapshot in (SNAP_DIFF, SNAP_SWAP):
            sdata = XWsnapshot.get(addr)
            if sdata is not None and sdata != data:
                # highlight the text somehow
                pre = '\x1b[7m'
                post = '\x1b[27m'

        if snapshot in (SNAP_CAP, SNAP_SWAP):
            XWsnapshot[addr] = data
        output.append(pre + bs[i*4:(i*4)+4].encode('hex') + post)

        if ((i+1) % dwperline == 0):
            output.append("\n")
        else:
            output.append("  ")

    return "".join(output)


PriRegSnapshot = {}
def showPriRegisters(emu, snapshot=SNAP_NORM):
    global PriRegSnapshot
    print "\nRegisters:"
    reggrps = emu.vw.arch.archGetRegisterGroups()
    for name, gen_regs in reggrps:
        if name == 'general':
            break

    reg_table, meta_regs, PC_idx, SP_idx, reg_vals = emu.getRegisterInfo()
    reg_dict = {reg_table[i][0]: (reg_table[i][1], reg_vals[i]) for i in range(len(reg_table))}

    # print through the various registers
    for i in range(len(gen_regs)):
        rname = gen_regs[i]
        rsz, rval = reg_dict.get(rname)

        # line break every so often
        if (i % 5 == 0):
            sys.stdout.write("\n")#%4x"%i)

        # do snapshotting:
        pre = post = ''
        if snapshot in (SNAP_DIFF, SNAP_SWAP):
            srval = XWsnapshot.get(rname)
            if srval is not None and srval != rval:
                # highlight the text somehow
                pre = '\x1b[7m'
                post = '\x1b[27m'

        if snapshot in (SNAP_CAP, SNAP_SWAP):
            XWsnapshot[rname] = rval

        rnpad = ' ' * (11 - len(rname))

        fmt = "%%s%%s: %%%dx%%s" % (rsz/4)
        sys.stdout.write(fmt % (rnpad, pre + rname, rval, post))

    # Line feed
    print "\n"


def showFlags(self):
    """
    Show the contents of the Status Register
    """
    # print "\tStatus Flags: \tRegister: %s\n" % (bin(self.getStatusRegister()))
    print "\tStatFlags: " + '\t'.join(["%s %s" % (f, v) for f, v in self.getStatusFlags().items()])


def stackDump(emu):
    print("Stack Dump:")
    sp = emu.getStackCounter()
    for x in range(16):
        print("\t0x%x:\t0x%x" % (sp, emu.readMemValue(sp, emu.psize)))
        sp += emu.psize

def parseExpression(emu, expr, lcls={}):
    '''
    localized updated expression parser for the emulator at any state
    '''
    lcls = emu.vw.getExpressionLocals()
    lcls.update(emu.getRegisters())
    return e_expr.evaluate(expr, lcls)

'''
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
            print repr(eval(tdata))
        except Exception as e:
            print "TraceMonitor ERROR at 0x%x: %r" % (starteip, e)
'''

call_handlers = {}
def runStep(emu, maxstep=1000000, follow=True, showafter=True, runTil=None, pause=True, silent=False, finish=0, tracedict=None):
    global op, mcanv, call_handlers

    mcanv = e_memcanvas.StringMemoryCanvas(emu, syms=emu.vw)
    if tracedict is None:
        tracedict = {}
    else:
        print "tracedict entries for %r" % (','.join([hex(key) for key in tracedict.keys() if type(key) in (int,long)]))

    nonstop = 0
    tova = None
    quit = False
    moveon = False
    emuBranch = False

    silentExcept = [va for va, expr in tracedict.items() if expr is None]

    i = 0
    while maxstep > i:
        skip = skipop = False
        i += 1

        pc=emu.getProgramCounter()
        if pc in (runTil, finish):
            break

        op=emu.parseOpcode(pc)

        # cancel emuBranch as we've come to one
        if op.isReturn() or op.isCall():
            emuBranch = False

        #### TRACING 
        tdata = tracedict.get(pc)
        if tdata is not None:
            try:
                lcls = locals()
                outlcls = tracedict.get('locals')
                if outlcls is not None:
                    lcls.update(outlcls)

                print repr(eval(tdata, globals(), lcls))
            except Exception as e:
                print "TraceMonitor ERROR at 0x%x: %r" % (pc, e)

        ####

        if silent and not pc in silentExcept:
            showafter = False
        else:
            # do all the interface stuff here:
            showPriRegisters(emu, snapshot=SNAP_SWAP)
            #showFlags(emu) # ARM fails this right now.
            opbytes = emu.readMemory(pc,len(op))
            try:
                printMemStatus(emu, op)
            except Exception as e:
                print "MEM ERROR: %s:    0x%x %s" % (e, op.va, op)

            print "Step: %s" % i
            mcanv.clearCanvas()
            try:
                op.render(mcanv)
            except Exception as e:
                print "ERROR rendering opcode: %r" % e

            extra = getNameRefs(op, emu)

            print("%.4x\t%20s\t%s\t%s"%(pc,sp.hexText(opbytes),mcanv.strval, extra))

            print "---------"
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
                moveon = False

                uinp = raw_input(prompt)
                while len(uinp) and not (moveon or quit or emuBranch):
                    if uinp == "q":
                        quit = True
                        break
                    elif uinp.startswith('go '):
                        args = uinp.split(' ')
                        if args[-1].startswith('+'):
                            nonstop = int(args[-1],0)
                        else:
                            tova = int(args[-1],0)
                            nonstop = 1
                        break

                    elif uinp in ('b', 'branch'):
                        emuBranch = True
                        break

                    elif uinp == 'stack':
                        stackDump(emu)
                        break

                    elif uinp == 'refresh':
                        # basically does a NOP, doesn't change anything, just let the data be reprinted.
                        moveon = True
                        break

                    elif uinp.startswith('pc=') or uinp.startswith('pc ='):
                        print "handling setProgramCounter()"
                        args = uinp.split('=')
                        newpc = int(args[-1], 0)
                        print "new PC: 0x%x" % newpc
                        emu.setProgramCounter(newpc)
                        moveon = True
                        break

                    elif '=' in uinp:
                        print "handling generic register/memory writes"
                        args = uinp.split('=')
                        data = args[-1].strip() #   .split(',')  ??? why did i ever do this?

                        if '[' in args[0]:
                            # memory derefs
                            tgt = args[0].replace('[','').replace(']','').split(':')
                            if len(tgt) > 1:
                                size = parseExpression(emu, tgt[-1], emu.getRegisters())
                            else:
                                size = 4

                            addrstr = tgt[0]
                            memaddr = parseExpression(emu, addrstr, emu.getRegisters())

                            if data.startswith('"') and data.endswith('"'):
                                # write string data
                                emu.writeMemory(memaddr, data[1:-1])
                            else:
                                # write number
                                emu.writeMemValue(memaddr, parseExpression(emu, data, emu.getRegisters()), size)

                        else:
                            # must be registers
                            emu.setRegisterByName(args[0], parseExpression(emu, data, emu.getRegisters()))

                    elif uinp.strip().startswith('[') and ']' in uinp:
                        try:
                            idx = uinp.find('[') + 1
                            eidx = uinp.find(']', idx)
                            expr = uinp[idx:eidx]
                            print "handling memory read at [%s]" % expr
                            size = emu.getPointerSize()
                            if ':' in expr:
                                nexpr, size = expr.rsplit(':',1)
                                try:
                                    size = parseExpression(emu, size)
                                    expr = nexpr
                                except:
                                    # if number fails, just continue with a default size and the original expr
                                    pass

                            va = parseExpression(emu, expr)
                            data = emu.readMemory(va, size)
                            print "[%s:%s] == %r" % (expr, size, data.encode('hex'))
                        except Exception as e:
                            print "ERROR: %r" % e

                    elif uinp == 'skip':
                        newpc = emu.getProgramCounter() + len(op)
                        print "new PC: 0x%x" % newpc
                        skipop = True
                        break
                    elif uinp == 'memset':
                        print memset(emu)
                        skipop = True
                    elif uinp == 'memcpy':
                        print memcpy(emu)
                        skipop = True
                    elif uinp == 'strcpy':
                        print strcpy(emu)
                        skipop = True
                    elif uinp == 'strncpy':
                        print strncpy(emu)
                        skipop = True
                    elif uinp == 'strcat':
                        print strcat(emu)
                        skipop = True
                    elif uinp == 'strlen':
                        print strlen(emu)
                        skipop = True
                    else:
                        try:
                            lcls = locals()
                            lcls.update(emu.getRegisters())
                            print eval(uinp, globals(), lcls)
                        except:
                            sys.excepthook(*sys.exc_info())

                    uinp = raw_input(prompt)

        if quit:
            return

        if moveon:
            continue

        if len(op.opers) and op.iflags & (envi.IF_CALL) and not skipop:
            if not silent: print "Call..."
            tva = op.getOperValue(0, emu)
            handler = call_handlers.get(tva)
            if not silent: print " handler for call to (0x%x): %r" % (tva, handler)
            if handler is not None:
                handler(emu, op)
                skipop = True

            elif follow and not skip and not skipop:
                # use the emulator to execute the call
                starteip = emu.getProgramCounter()
                emu.executeOpcode(op)
                endeip = emu.getProgramCounter()
                i += 1

                if not silent: print "starteip: 0x%x, endeip: 0x%x  -> %s" % (starteip, endeip, emu.vw.getName(endeip))
                vg_path.getNodeProp(emu.curpath, 'valist').append(starteip)
                skip = True

        if not skip and not skipop:
            # if not already emulated a call, execute the instruction here...
            emu.stepi()

            # print the updated latest stuff....
            if showafter:
                try:
                    extra = getNameRefs(op, emu)
                    if len(extra):
                        print("after:\t%s\t%s"%(mcanv.strval, extra))

                    printMemStatus(emu, op, use_cached=True)
                except Exception as e:
                    print "MEM ERROR: %s:    0x%x %s" % (e, op.va, op)

        elif skipop:
            newpc = emu.getProgramCounter() + len(op)
            emu.setProgramCounter(newpc)
        #prtInst(emu)
        #showPriRegisters(emu)
        #showFlags(emu)

def getNameRefs(op, emu):
    extra = ''
    ###  HACK: NOT FOR PUBLIC CONSUMPTION:
    #taintPause = emu._pause_on_taint
    #emu._pause_on_taint = False
    try:

        for operidx, oper in enumerate(op.opers):
            opval = oper.getOperValue(op, emu)
            if type(opval) in (int, long):
                opnm = emu.vw.getName(opval)
                if opnm is None:
                    opnm = emu.getVivTaint(opval)

                if opnm is not None:
                    extra += '\t; $%d = %r' % (operidx, opnm)

            dopval = oper.getOperAddr(op, emu)
            if type(dopval) in (int, long):
                dopnm = emu.vw.getName(dopval)
                if opnm is None:
                    opnm = emu.getVivTaint(opval)

                if dopnm is not None:
                    extra += '\t; &$%d = %r' % (operidx, dopnm)
    except Exception as e:
        print "getNameRefs: ERROR: %r" % e
    finally:
        #emu._pause_on_taint = taintPause
        pass
    return extra

def runUntil(emu, eip=0, mnem="int", maxstep=1000000):
    global op
    for i in range(maxstep):
        pc=emu.getProgramCounter()
        op=emu.parseOpcode(pc)
        opbytes = emu.readMemory(pc,len(op))
        if pc == eip or op.mnem == mnem:
            break
        emu.stepi()
    runStep(emu)

def printWriteLog(emu):
    print '\n'.join(['0x%.8x: 0x%.8x << %32r %r' % (x,y,d.encode('hex'),d) for x,y,d in emu.path[2].get('writelog')])

def selectTest():

    print "The following tests implement T80515 disassembly or emulation.\n\n"

    print "Select Test: \n[0] Disassemble Only \n[1] Emulation \n",
    dotest = raw_input()
    if dotest.isdigit():
        return int(dotest)
    else:
        print "Unknown test selected"
        sys.exit()

class Iemu(cmd.Cmd):
    '''
    wraps an emulator with some basic interface stuff
    '''
    def __init__(self, emu):
        cmd.Cmd.__init__(self)
        self.repeat = True
        self.emu = emu

        self.context = {}
        self.context['cli'] = self
        self.context['emu'] = self.emu

    def go(self, pc=None, regs=None, mem=None):
        if pc is not None:
            self.emu.setProgramCounter(pc)

        if regs is not None:
            for reg,val in regs.items():
                self.emu.setRegister(reg, val)

        if mem is not None:
            for va,data in mem.items():
                self.emu.writeMemory(va, data)

        self.cmdloop()

    def do_quit(self, line):
        return False


    def emptyline(self):
        if self.repeat:
            cmd.Cmd.emptyline(self)

        else:
            self.do_help("HELP!")

    def default(self, line):
        info = self.parseline(line)
        self.context.update(locals())

        try:
            output = eval(line, globals(), context)
        except KeyboardException:
            self.do_quit()

        print ">> " + output

    def do_run(self, line):
        count = 30
        if len(line.strip()):
            count = int(line)

        runStep(self.emu, count)

    def do_rununtil(self, line):
        va = None
        mnem = 'int'

        try:
            if '0x' in line:
                va = int(line, 16)
            else:
                va = int(line)
        except ValueError:
            mnem = line.strip()

        runUntil(self.emu, eip=va, mnem=mnem)

def readString(emu, va, CHUNK=50):
    off = 0
    out = [ emu.readMemory(va + off, CHUNK) ]
    while '\0' not in out[-1]:
        off += CHUNK
        data = emu.readMemory(va + off, CHUNK)
        out.append(data)

    data = ''.join(out)

    return data[:data.find('\0')]

#### WOW these are fux0rd.  ARM specific.  FIXME: use calling convention stuff.
def memset(emu, op=None):
    data = ('%c' % emu.getRegisterByName('r1')) * emu.getRegisterByName('r2')
    emu.writeMemory(emu.getRegisterByName('r0'), data)
    print data
    return data

def memcpy(emu, op=None):
    data = emu.readMemory(emu.getRegisterByName('r1'), emu.getRegisterByName('r2'))
    emu.writeMemory(emu.getRegisterByName('r0'), data)
    print data
    return data

def strncpy(emu, op=None):
    data = emu.readMemory(emu.getRegisterByName('r1'), emu.getRegisterByName('r2'))
    nulloc = data.find('\0')
    if nulloc != -1:
        data = data[:nulloc]
    emu.writeMemory(emu.getRegisterByName('r0'), data)
    print data
    return data

def strcpy(emu, op=None):
    data = readString(emu, emu.getRegisterByName('r1')) + '\0'
    emu.writeMemory(emu.getRegisterByName('r0'), data)
    print data
    return data

def strcat(emu, op=None):
    start = emu.getRegisterByName('r0')
    initial = readString(emu, start)
    data = readString(emu, emu.getRegisterByName('r1'))
    emu.writeMemory(start + len(initial), data)
    print initial+data
    return initial+data

def strlen(emu, op=None):
    data = readString(emu, emu.getRegisterByName('r0'))
    emu.setRegisterByName('r0', len(data))
    print len(data)
    return len(data)

allocated_ptr = 0x10000000
def malloc(emu, op=None):
    global allocated_ptr
    emu.setRegisterByName('r0', allocated_ptr)
    allocated_ptr += 0x1000
    
def skip(emu, op):
    emu.setProgramCounter(emu.getProgramCounter()+len(op))

def ret0(emu, op):
    emu.setRegisterByName('r0', 0)

def ret1(emu, op):
    emu.setRegisterByName('r0', 1)

def retneg1(emu, op):
    emu.setRegisterByName('r0', -1)




def syslog(emu, op=None):
    loglvl = emu.getRegisterByName('r0')
    string = readString(emu, emu.getRegisterByName('r1'))
    count = string.count('%')
    neg2 = string.count('%%')
    count -= (2*neg2)

    args = tuple([emu.getRegister(x) for x in range(2, 2+count)])
    outstring = string % args
    print "SYSLOG(%d): %s" % (loglvl, outstring)
    for s in args:
        if emu.isValidPointer(s):
            print "\t" + readString(emu, s)


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

        out1.append(data1[x].encode('hex'))
        out2.append(data2[x].encode('hex'))
   
    if len(data1) > len(data2):
        out1.append(data1[x:].encode('hex'))
    elif len(data1) > len(data2):
        out2.append(data2[x:].encode('hex'))
    
    if not lastres:
        out1.append(posthilite)
        out2.append(posthilite)

    print ''.join(out1)
    print ''.join(out2)


class TestEmulator:
    def __init__(self, emu, verbose=False):
        self.XWsnapshot = {}
        self.call_handlers = {}
        self.verbose = verbose
        self.emu = emu

    def XW(self, tracer, address, length = 32, dwperline = 8, snapshot=0):

        output = []
        mm = tracer.getMemoryMap(address)
        if mm is None:
            return ''

        mmva, mmsz, mmperm, mmname = mm
        if mmva+mmsz < address + (length*4):
            goodbcnt = (mmva+mmsz-address)
            diff = (length*4) - goodbcnt
            bs = tracer.readMemory(address, goodbcnt)
            bs += 'A' * diff

        else:
            bs = tracer.readMemory(address, length*4)

        for i in range(length):
            addr = address + (i * 4)
            if (i % dwperline == 0):
                output.append( "%.08x:\t "%(addr))

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
            output.append(pre + bs[i*4:(i*4)+4].encode('hex') + post)

            if ((i+1) % dwperline == 0):
                output.append("\n")
            else:
                output.append("  ")

        return "".join(output)


    def showPriRegisters(self, emu, snapshot=SNAP_NORM):
        print "\nRegisters:"
        reggrps = emu.vw.arch.archGetRegisterGroups()
        for name, gen_regs in reggrps:
            if name == 'general':
                break

        reg_table, meta_regs, PC_idx, SP_idx, reg_vals = emu.getRegisterInfo()
        reg_dict = { reg_table[i][0] : (reg_table[i][1], reg_vals[i]) for i in range(len(reg_table)) }

        # print through the various registers
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

            fmt = "%%s%%s: %%%dx%%s" % (rsz/4)
            sys.stdout.write(fmt % (rnpad, pre + rname, rval, post))

        # Line feed
        print "\n"

    def showFlags(self):
        """
        Show the contents of the Status Register
        """
        #print "\tStatus Flags: \tRegister: %s\n" % (bin(self.getStatusRegister()))
        print "\tStatFlags: " + '\t'.join(["%s %s" % (f,v) for f,v in self.emu.getStatusFlags().items()])


    def stackDump(self):
        emu = self.emu
        print("Stack Dump:")
        sp = emu.getStackCounter()
        for x in range(16):
            print("\t0x%x:\t0x%x" % (sp, emu.readMemValue(sp, emu.psize)))
            sp += emu.psize


    def runStep(self, maxstep=1000000, follow=True, showafter=True, runTil=None, pause=True, silent=False, finish=0, silentExcept=()):
        global op, mcanv, call_handlers
        emu = self.emu

        mcanv = e_memcanvas.StringMemoryCanvas(emu, syms=emu.vw)

        nonstop = 0
        tova = None
        quit = False
        moveon = False
        emuBranch = False

        i = 0
        while maxstep > i:
            skip = skipop = False
            i += 1

            pc=emu.getProgramCounter()
            if pc in (runTil, finish):
                break

            op=emu.parseOpcode(pc)

            # cancel emuBranch as we've come to one
            if op.isReturn() or op.isCall():
                emuBranch = False

            if silent and not pc in silentExcept:
                showafter = False
            else:
                # do all the interface stuff here:
                showPriRegisters(emu, snapshot=SNAP_SWAP)
                #showFlags(emu) # ARM fails this right now.
                try:
                    printMemStatus(emu, op)
                except Exception as e:
                    print "MEM ERROR: %s:    0x%x %s" % (e, op.va, op)

                print "Step: %s" % i
                mcanv.clearCanvas()
                try:
                    op.render(mcanv)
                except Exception as e:
                    print "ERROR rendering opcode: %r" % e

                extra = getNameRefs(op, emu)

                opbytes = emu.readMemory(pc,len(op))
                print("%.4x\t%20s\t%s\t%s"%(pc,sp.hexText(opbytes),mcanv.strval, extra))

                print "---------"
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
                    moveon = False

                    uinp = raw_input(prompt)
                    while len(uinp) and not (moveon or quit or emuBranch):
                        if uinp == "q":
                            quit = True
                            break
                        elif uinp.startswith('go '):
                            args = uinp.split(' ')
                            if args[-1].startswith('+'):
                                nonstop = int(args[-1],0)
                            else:
                                tova = int(args[-1],0)
                                nonstop = 1
                            break

                        elif uinp in ('b', 'branch'):
                            emuBranch = True
                            break

                        elif uinp == 'stack':
                            stackDump(emu)
                            break

                        elif uinp == 'refresh':
                            # basically does a NOP, doesn't change anything, just let the data be reprinted.
                            moveon = True
                            break

                        elif uinp.startswith('pc=') or uinp.startswith('pc ='):
                            print "handling setProgramCounter()"
                            args = uinp.split('=')
                            newpc = int(args[-1], 0)
                            print "new PC: 0x%x" % newpc
                            emu.setProgramCounter(newpc)
                            moveon = True
                            break

                        elif '=' in uinp:
                            print "handling generic register/memory writes"
                            args = uinp.split('=')
                            data = args[-1].strip() #   .split(',')  ??? why did i ever do this?

                            if '[' in args[0]:
                                # memory derefs
                                tgt = args[0].replace('[','').replace(']','').split(':')
                                if len(tgt) > 1:
                                    size = parseExpression(emu, tgt[-1], emu.getRegisters())
                                else:
                                    size = 4

                                addrstr = tgt[0]
                                memaddr = parseExpression(emu, addrstr, emu.getRegisters())

                                if data.startswith('"') and data.endswith('"'):
                                    # write string data
                                    emu.writeMemory(memaddr, data[1:-1])
                                else:
                                    # write number
                                    emu.writeMemValue(memaddr, parseExpression(emu, data, emu.getRegisters()), size)

                            else:
                                # must be registers
                                emu.setRegisterByName(args[0], parseExpression(emu, data)

                        elif uinp.strip().startswith('[') and ']' in uinp:
                            try:
                                idx = uinp.find('[') + 1
                                eidx = uinp.find(']', idx)
                                expr = uinp[idx:eidx]
                                print "handling memory read at [%s]" % expr
                                size = emu.getPointerSize()
                                if ':' in expr:
                                    nexpr, size = expr.rsplit(':',1)
                                    try:
                                        size = parseExpression(emu, size)
                                        expr = nexpr
                                    except Exception as e:
                                        # if number fails, just continue with a default size and the original expr
                                        print "unknown size: %r.  using default size." % size

                                va = parseExpression(emu, expr)
                                data = emu.readMemory(va, size)
                                print "[%s:%s] == %r" % (expr, size, data.encode('hex'))
                            except Exception as e:
                                print "ERROR: %r" % e

                        elif uinp == 'skip':
                            newpc = emu.getProgramCounter() + len(op)
                            print "new PC: 0x%x" % newpc
                            skipop = True
                            break
                        elif uinp == 'memset':
                            print memset(emu)
                            skipop = True
                        elif uinp == 'memcpy':
                            print memcpy(emu)
                            skipop = True
                        elif uinp == 'strcpy':
                            print strcpy(emu)
                            skipop = True
                        elif uinp == 'strncpy':
                            print strncpy(emu)
                            skipop = True
                        elif uinp == 'strcat':
                            print strcat(emu)
                            skipop = True
                        elif uinp == 'strlen':
                            print strlen(emu)
                            skipop = True
                        else:
                            try:
                                lcls = locals()
                                lcls.update(emu.getRegisters())
                                print eval(uinp, globals(), lcls)
                            except:
                                sys.excepthook(*sys.exc_info())

                        uinp = raw_input(prompt)

            if quit:
                return

            if moveon:
                continue

            if len(op.opers) and op.iflags & (envi.IF_CALL) and not skipop:
                self.dbgprint ("Call...")
                tva = op.getOperValue(0, emu)
                handler = self.call_handlers.get(tva)
                self.dbgprint( " handler for call to (0x%x): %r" % (tva, handler))
                if handler is not None:
                    handler(emu, op)
                    skipop = True

                elif follow and not skip and not skipop:
                    # use the emulator to execute the call
                    starteip = emu.getProgramCounter()
                    emu.executeOpcode(op)
                    endeip = emu.getProgramCounter()
                    i += 1

                    self.dbgprint ("starteip: 0x%x, endeip: 0x%x  -> %s" % (starteip, endeip, emu.vw.getName(endeip)))
                    vg_path.getNodeProp(emu.curpath, 'valist').append(starteip)
                    skip = True

            if not skip and not skipop:
                # if not already emulated a call, execute the instruction here...
                emu.stepi()

                # print the updated latest stuff....
                if showafter:
                    try:
                        extra = getNameRefs(op, emu)
                        if len(extra):
                            print("after:\t%s\t%s"%(mcanv.strval, extra))

                        printMemStatus(emu, op, use_cached=True)
                    except Exception as e:
                        print "MEM ERROR: %s:    0x%x %s" % (e, op.va, op)

            elif skipop:
                newpc = emu.getProgramCounter() + len(op)
                emu.setProgramCounter(newpc)
            #prtInst(emu)
            #showPriRegisters(emu)
            #showFlags(emu)

    def dbgprint(self, *args, **kwargs):
        if self.verbose:
            data = '\t'.join(args)
            print(data)

    def getNameRefs(op, emu):
        extra = ''
        ###  HACK: NOT FOR PUBLIC CONSUMPTION:
        taintPause = emu._pause_on_taint
        emu._pause_on_taint = False
        try:

            for operidx, oper in enumerate(op.opers):
                opval = oper.getOperValue(op, emu)
                if type(opval) in (int, long):
                    opnm = emu.vw.getName(opval)
                    if opnm is None:
                        opnm = emu.getVivTaint(opval)

                    if opnm is not None:
                        extra += '\t; $%d = %r' % (operidx, opnm)

                dopval = oper.getOperAddr(op, emu)
                if type(dopval) in (int, long):
                    dopnm = emu.vw.getName(dopval)
                    if opnm is None:
                        opnm = emu.getVivTaint(opval)

                    if dopnm is not None:
                        extra += '\t; &$%d = %r' % (operidx, dopnm)
        except Exception as e:
            print "getNameRefs: ERROR: %r" % e
        finally:
            emu._pause_on_taint = taintPause
        return extra

    def runUntil(emu, eip=0, mnem="int", maxstep=1000000):
        global op
        for i in range(maxstep):
            pc=emu.getProgramCounter()
            op=emu.parseOpcode(pc)
            opbytes = emu.readMemory(pc,len(op))
            if pc == eip or op.mnem == mnem:
                break
            emu.stepi()
        runStep(emu)

    def printWriteLog(emu):
        print '\n'.join(['0x%.8x: 0x%.8x << %32r %r' % (x,y,d.encode('hex'),d) for x,y,d in emu.path[2].get('writelog')])


if __name__ == "__main__":
    main(sys.argv)

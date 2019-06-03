#!/usr/bin/ipython  -i
import envi.memory as e_mem
import envi.archs.i386 as x86
import envi.archs.i386.emu as x86emu
from envi.archs.i386 import REG_EAX,REG_EBX,REG_ECX,REG_EDX,REG_ESI,REG_EDI,REG_EIP,REG_ESP,REG_EBP
import sys,struct


DEF_STACK_SIZE = 1024*1024
DEF_STACK_BASE = 0xc0000000
DEF_CODE_BASE = 0x8048100
a = x86.i386Module()

def opnum(num):
    return a.makeOpcode(struct.pack("<L", num))


def disass(bytes):
    offset = 0
    try:
        while True:
            op = a.makeOpcode(bytes, offset)
            nibble = bytes[offset:offset+len(op)]
            print "%8x\t%-20s\t%.20s"%(offset, nibble.encode('hex'), op)
            offset += len(op)
    except Exception, e:
        print "ERROR OCCURRED: %s" % repr(e)

class SuccessfulRunException(Exception): pass

class IEmulator(x86emu.IntelEmulator):
    def __init__(self, maps=[]):
        global a
        x86emu.IntelEmulator.__init__(self)
        self.imem_arch = a

        for mva,mperms,mnm,mbytes in maps:
            self.addMemoryMap(mva, mperms, mnm, mbytes)
            if mnm == '[stack]':
                self.setStackCounter(mva + len(mbytes) - 40)
                self.setRegister(REG_EBP, mva + len(mbytes) - 40)

        if len(maps):
            self.setProgramCounter(maps[0][0])

    def run(self, stepcount=None, tova=None):

        print self
        if stepcount != None:
            for i in xrange(stepcount):
                try:
                    self.stepi()
                    if tova is not None and self.getProgramCounter() == tova:
                        raise(SuccessfulRunException("Found VA"))
                except SuccessfulRunException, e:
                    print e
                    return
        else:
            while True:
                try:
                    self.stepi()
                    if tova is not None and self.getProgramCounter() == tova:
                        raise(SuccessfulRunException("Found VA"))
                except SuccessfulRunException, e:
                    print e
                    return


    def stepi(self):
        x86emu.IntelEmulator.stepi(self)
        print self

    def __str__(self):
        return self.getString()

    def getString(me, eachThread=False, width=8):
        output = []
        ebp= me.getRegister(REG_EBP)
        esp= me.getRegister(REG_ESP)
        eax= me.getRegister(REG_EAX)
        ebx= me.getRegister(REG_EBX)
        ecx= me.getRegister(REG_ECX)
        edx= me.getRegister(REG_EDX)
        esi= me.getRegister(REG_ESI)
        edi= me.getRegister(REG_EDI)
        eip= me.getProgramCounter() 
        
        output.append("\nesp: (%x)\n" % esp)
        try:
            output.append( me.XW(esp, 64, width) )
        except Exception, e:
            output.append("ERROR READING FROM MEMORY AT %x\n"%(esp) + repr(e))
        
        output.append( "\nebp-92: " + "(%x)\n" % esp )
        try:
            output.append(me.XW(ebp-92, 64, width))
        except Exception, e:
            output.append("ERROR READING FROM MEMORY AT %x\n"%(ebp-92) + repr(e))
        
        for i in ['eax','ecx','edx','ebx','esi','edi']:
            output.append("%s: %.08x\t"%(i,locals().get(i)))

        op = me.parseOpcode(eip)
        opers = []
        for oidx in range(len(op.opers)):
            try:
                opers.append("(%x)" % me.getOperAddr(op, oidx))
            except Exception,e:
                pass#print e
            opers.append(hex(me.getOperValue(op, oidx)))
        cmd = ' '.join(opers)
        output.append( "\neip: %.08x: %-30s\t\t\t%s"%(eip, op, cmd))
        output.append( "\n\t(%8x (%x): %d  %s)"%me.getMemoryMap(eip))
        return ''.join(output)

    def XW(tracer, address, length = 32, dwperline = 8):
        output = []
        for i in range(length):
            if (i % dwperline == 0):
                output.append( "%.08x:\t "%(address+(i*4)))
            try:
                bs = tracer.readMemory(address+(i*4),4)
                for x in range(4):
                    output.append("%.02x"%(ord(bs[x])))
            except:
                output.append("=-=-=-=-")

            if ((i+1) % dwperline == 0):
                output.append("\n")
            else:
                output.append("  ")
        return "".join(output)


def geti386Emulator(bytes, codebase=DEF_CODE_BASE, stackbase=DEF_STACK_BASE, stacksize=DEF_STACK_SIZE):
    maps = [(codebase, 5, 'program',  bytes),
            (stackbase-stacksize, 6, '[stack]', "D" * stacksize)]
    emu = IEmulator(maps)
    #emu.setStackCounter(stackbase - 4)
   
    return emu


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == "-o":
        sys.argv.pop(1)
        offset = int(sys.argv.pop(1))

    if len(sys.argv) > 1:
        print "Reading instructions from file %s"%sys.argv[1]
        inf = file(sys.argv[1], "rb")
    else:
        print "Reading instructions from stdin..."
        inf = sys.stdin

    bytes = inf.read()
    disass(bytes)


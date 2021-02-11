#!/usr/bin/python -i

from atlasutils.vtraceutils import  *
from atlasutils.smartprint import  *
import os,sys,time
try:
    from pefile import *
except:
    from Elf import *


class LibraryNotifier(vtrace.Notifier):
    """
    A small example notifier which prints
    out libraries as they are loaded.
    """
    def notify(self, event, trace):
        if event == vtrace.NOTIFY_LOAD_LIBRARY:
            print("-----Library Loaded:",trace.getMeta("LatestLibrary"))


class tracebin:

    def __init__(self, name, trace=None, verbose = False):
        self.binexe = name.split(os.sep)[-1]
        self.verbose = verbose
        self.locsec = None
        self.bin = None
        self.startaddress = None
        self.eip = 0
        self.lastcall = (0,0)   # last target and last source address
        if os.name == 'posix':
            self.bin = Elf(argv[1])
            self.startaddress = self.bin.e_entry
        elif os.name == 'nt':
            self.bin = PE(argv[1])
            self.startaddress = self.bin.OPTIONAL_HEADER.AddressOfEntryPoint + self.bin.OPTIONAL_HEADER.ImageBase
        
        self.me = getTrace()
        self.me.registerNotifier(NOTIFY_EXIT, VerboseNotifier())
        self.me.registerNotifier(NOTIFY_BREAK, VerboseNotifier())
        self.me.registerNotifier(NOTIFY_LOAD_LIBRARY, LibraryNotifier())
        self.me.addBreakpoint(Breakpoint(self.startaddress))      # This should get us past the loader code into the actual start of the binary
        self.me.metadata['RUN'] = True
        self.me.execute(argv[1])
        
        #self.startaddress += 2           # skip prolog
        
            
    def isLocal(self, address):
        if not self.locsec:
            if os.name[0] == 'p':
                self.genLocalLinux()
            elif os.name[0] == 'n':
                self.genLocalWin()
            else:
                self.genLocalDefault()
                
        for x in self.locsec:
            if address >= x[0] and address <= x[1]:
                return True
        return False
    
    def genLocalLinux(self):
        self.locsec = []
        for sec in self.bin.getSections():
            if (sec.sh_flags & 4 and sec.name[:4] != '.plt' and sec.name[:5] != '.init'):
                start = sec.sh_addr
                end   = sec.sh_addr+sec.sh_size
                print ("    appending 'local' section...  %s (%x - %x)"%(sec.name, start, end))
                self.locsec.append((start, end))
        return True
            
    def genLocalWin(self):
        self.locsec = []
        for sec in self.bin.sections:
            if (sec.Name[:5].lower() == '.text' or sec.Characteristics & 0x20000000 ):
                start = sec.VirtualAddress + self.bin.OPTIONAL_HEADER.ImageBase
                end   = sec.VirtualAddress + self.bin.OPTIONAL_HEADER.ImageBase + sec.SizeOfRawData
                print("    appending 'local' section...  %s (%x-%x)"%(sec.Name, start, end))
                self.locsec.append((start, end))
        return True
    def genLocalDefault(self):
        #locsec = []
        mytextstart = 0xffffffff
        mytextend = 0
        for x in self.me.getMemoryMaps():
            if binexe in x[3]:
                print ("Tracing:  %s compare %x to %s at %x"%(binexe,mytextstart,x[3], x[0]))
                if mytextstart > x[0]:
                    mytextstart = x[0]
                if mytextend < (x[0]+x[1]):
                    mytextend = (x[0]+x[1])
        self.locsec = [(mytextstart,mytextend)]
        
    def getOperandValue(self, operand):
        dereference = False
        add = ""
        numaddr = 0
        source = operand
        if isinstance(source, SIB):
            if source.index:
                numaddr += (source.index * source.scale)
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
                if isinstance(source.index, Register):
                    numaddr += (self.getRegisterValue(source.index))
                else:
                    print source.index
                    numaddr += (source.index * source.scale)
            if source.base:
                source = source.base
            #print >>outfile,("DEBUG-sib: %x"%numaddr)
        if isinstance(source, Register):
            numaddr += (self.getRegisterValue(source))
            #print >>outfile,("DEBUG-reg: %x"%numaddr)
        elif isinstance(source, Address):
            numaddr += source.value
            if source.relative:
                numaddr += self.eip + self.op.off
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
        
    def getRegisterValue(self, source):
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
            return (self.me.getRegisterByName(reg) & mask)
            #print >>outfile,("DEBUG-reg: %x"%numaddr)

    def localstepi(self, outfile = stdout):
        me = self.me
        origThread = me.getMeta('ThreadId')
        threads = None
        while threads == None:
            try:
                threads = me.getThreads()
            except:
                print >>stderr,("Error: Thread list changed in middle of getThreads()")
        for t in threads:
            values = ""
            me.selectThread(t)
            me.stepi()
            self.eip = me.getProgramCounter()
            #print >>outfile,("debug: %x"%self.eip)
            try:
              self.op = Opcode(me.readMemory(self.eip, 18))
              if self.isLocal(self.eip):
                # LOCAL TO THIS BINARY's .TEXT SECTION
                values = "; "
                if self.op.dest:
                    if not isinstance(self.op.dest, Address):
                        num = self.getOperandValue(self.op.dest)
                    else:
                        num = self.op.dest.value
                        if self.op.dest.relative:
                            num += self.eip
                    temp = "\t%x"%num
                    if me.getMemoryMap(num) != None:
                        try:
                            temp += "=('%s'...)"%(hexText(me.readMemory(num, 10)))
                        except:
                            print("ERROR READING MEMORY AT %x:"%num)
                    values += " %s"%(temp)
                if self.op.source:
                    if not isinstance(self.op.source, Address):
                        num = self.getOperandValue(self.op.source)
                    else:
                        num = self.op.source.value
                        if self.op.source.relative:
                            num += self.eip
                    temp = "\t%x"%num
                    if me.getMemoryMap(num) != None:
                        try:
                            temp += "=('%s'...)"%(hexText(me.readMemory(num, 10)))
                        except:
                            print("ERROR READING MEMORY AT %x:"%num)
                    values += " %s"%(temp)
              print >>outfile,("thread %8d: %x   (%s)\t\t %s \t%s"%(t,self.eip,me.getSymByAddr(self.eip), self.op.printOpcode(0, self.eip), values))
              if self.op.opcode[:2] == "ca" or (self.op.opcode[0] == 'j' and abs(self.lastcall[0] - self.eip) < 4):
                dereference = False
                add = ""
                numaddr = 0
                source = self.op.source
                if isinstance(source, SIB):
                    numaddr += BREAKIT + source.index
                    source = source.index
                    print >>outfile,("DEBUG-sib: %x"%numaddr)
                if isinstance(source, Expression):
                    if source.disp:
                        numaddr += source.disp.value
                    if source.base:
                        source = source.base
                    dereference = True
                    print >>outfile,("DEBUG-expr: %x"%numaddr)
                if isinstance(source, Register):
                    numaddr += self.me.getRegisterByName(source.name)
                    print >>outfile,("DEBUG-reg: %x"%numaddr)
                elif isinstance(source, Address):
                    numaddr += source.value
                    if source.relative:
                        numaddr += self.eip + self.op.off
                    print >>outfile,("DEBUG-addr: %x"%numaddr)
                
                if dereference:
                    try:
                        numaddr = struct.unpack("L",me.readMemory(numaddr, 4))[0]
                        print >>outfile,("DEBUG-deref: %x"%numaddr)
                    except:
                        print >>outfile,("DEBUG-deref-except: %x"%numaddr)
                    
                target = me.getSymByAddr(numaddr)
                print >>outfile,("\t\t %x(%s) %s TO %s -- %x(%s)  \t\t\t (%s)"%(self.eip, self.isLocal(self.eip),self.op.opcode, self.op.source.printOpcode(0, self.eip), numaddr, self.isLocal(numaddr), target))
                try:    ### LINUX ONLY... fugly
                    if lookupPLT(numaddr) == '__libc_start_main':
                        main = struct.unpack("L", me.readMemory(me.getRegisterByName('esp'), 4))[0]
                        print >>outfile,("\t\t Setting main() Breakpoint at %x"%(main))
                        me.addBreakpoint(Breakpoint(main))
                except:
                    pass
                if not self.isLocal(numaddr) and self.isLocal(self.eip):
                    if self.op.opcode[0] == 'j':
                        baddr = self.lastcall[1]
                    else:
                        baddr = self.eip+self.op.off
                    brk = Breakpoint(baddr)
                    print >>outfile,("\t\t Going Remote...  Setting Breakpoint at %x"%(baddr))
                    try:
                        me.addBreakpoint(brk)
                    except:
                        pass
                    me.run()
                    print repr(me)
                    me.removeBreakpoint(brk)
                else:
                    self.lastcall = (numaddr, self.eip + self.op.off)
                #except:
                    #print >>stderr,("ERROR READING MEMORY LOCATION: %x"%eip)
            except:
                x,y,z = sys.exc_info()
                sys.excepthook(x,y,z)
        me.selectThread(origThread)
    
    
    
    
    
    
    
    def go(self, init = True):
        me = self.me
        #if init:
        print("Placing initial breakpoint at Entry Point: %x"%self.startaddress)
            #me.addBreakpoint(Breakpoint(self.startaddress))      # This should get us past the loader code into the actual start of the binary
            #while self.eip != self.startaddress:
            #    me.run()
            #    self.eip = me.getProgramCounter()
            #    print("Initial Stop at %x"%self.eip)
            #    time.sleep(1)
        
        if os.name =='nt':          # TAKE CARE OF ANTIDEBUGGING UNDER WINDOWS
            """
                >>> me.getSymByName('IsDebuggerPresent', 'kernel32')
                >>> idp=me.getSymByName('IsDebuggerPresent', 'kernel32')
                >>> while idp == None:
                    idp=me.getSymByName('IsDebuggerPresent', 'kernel32')
                    me.stepi()
                
                    
                >>> me.getProgramCounter()
                2089868385
                >>> "%x"%me.getProgramCounter()
                '7c90dc61'
                >>> 
            """
            idp = None
            print("Tracing until Kernel32 is loaded...")
            while idp == None:
                me.stepi()
                idp=me.getSymByName('IsDebuggerPresent', 'kernel32')
            print("Overwriting 'IsDebuggerPresent' to hide results")
            idp=me.getSymByName('isdebuggerpresent','kernel32').value
            me.writeMemory(idp, '\x33\xc0\xc3')     # %eax = 0, return
            
        while self.me.getMeta('RUN'): 
            try:
                self.localstepi()
            except KeyboardInterrupt:
                self.me.setMeta('RUN',False)
if __name__ == "__main__":                
  while (argv[1][0] == '-'):
    arg = argv.pop(1)
    if arg[1] == 'V':
        self.verbose = True
    else:
        print >>stderr,("ERROR: Unknown Parameter: %s"%arg)

  name = argv[1]
  tracebin(argv).go()


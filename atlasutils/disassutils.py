from sys import *
from atlasutils.props import *
from atlasutils.smartprint import *

try:
    from pydasm import *
except:
    print >>stderr,("pydasm not found, continuing anyway")

try:
    from disassemble import *
except:
    print >>stderr,("libdisassemble not found, continuing anyway")

try:
    import envi.archs.i386 as e_i386
    import envi.archs.i386.disasm as e_i386d
except:
    print >>stderr,("envi not found, continuing anyway")


from Elf import *


# pydasm stuff.
def g(STR):
    return get_instruction(STR,MODE_32)

def gs(STR):
    return get_instruction_string(g(STR), FORMAT_ATT, 0)

def disassPD(buffer, base = 0, mode = 32):
    """ Returns a list of tuples (address, instructionobject)
    """ 
    offset = 0
    opcodes = []
    if mode == 32:
        pydasm_mode = MODE_32
    elif mode == 16:
        pydasm_mode = MODE_16
    else:
        pydasm_mode = MODE_64

    while offset < len(buffer):
        i = get_instruction(buffer[offset:], pydasm_mode)
        #opcodes.append("%x: %s"%((base+offset), get_instruction_string(i, FORMAT_ATT, 0)))
        opcodes.append(((base+offset), i))
        if not i:
            return opcodes
        offset += i.length
    return opcodes

def disassPDdict(buffer, base = 0, mode = 32):
    offset = 0
    ops = props()
    if mode == 32:
        pydasm_mode = MODE_32
    elif mode == 16:
        pydasm_mode = MODE_16
    else:
        pydasm_mode = MODE_64

    while offset < len(buffer):
        i = get_instruction(buffer[offset:], pydasm_mode)
        if not i:
            return ops
        if (offset % 100 < 5): stderr.write(".")
        #ops.setdefault("%x"%((base+offset)),get_instruction_string(i, FORMAT_ATT, 0))
        ops["%x"%(base+offset)] = i
        offset += i.length
    return ops


def disassLD(buffer, offset=0, base = 0, mode = 32):
    """ Returns a list of tuples (address, instructionobject)
    """ 
    opcodes = []
    last = None
    prev = None
    o = None
    while offset < len(buffer):
        prev = last
        last = o
        o = Opcode(buffer, offset, mode)
        #opcodes.append("%x: %s\t %s"%((base+offset),"",o.printOpcode("AT&T",30)))
        opcodes.append(((base+offset), o))
        print repr(o)
        if o == None:
            return opcodes
        offset += o.getSize()
    return opcodes

def disassLDdict(buffer, base = 0, mode = 32):
    opcodes = props()
    offset = 0
    last = None
    prev = None
    o = None
    while offset < len(buffer):
        prev = last
        last = o
        o = Opcode(buffer, offset, mode)
        if not o:
            return opcodes
        if (offset % 100 < 5): stderr.write(".")
        #opcodes.setdefault("%x"%((base+offset)),o.printOpcode("AT&T",30))
        opcodes["%x"%(base+offset)] = o
        if o.getSize() > 0:
            offset += o.getSize()
        else:
            offset += 1
    return ops
    
def disassENVI(buffer, base = 0, mode = 32):
    opcodes = props()
    offset = 0
    last = None
    prev = None
    o = None
    while offset < len(buffer):
        prev = last
        last = o
        o = Opcode(buffer, offset, mode)
        if not o:
            return opcodes
        if (offset % 100 < 5): stderr.write(".")
        #opcodes.setdefault("%x"%((base+offset)),o.printOpcode("AT&T",30))
        opcodes["%x"%(base+offset)] = o
        if o.getSize() > 0:
            offset += o.getSize()
        else:
            offset += 1
    return ops


testbuffers = []
testbuffers.append( "\x8A\x4D\x0C")                   #       mov           0xc(%ebp), %cl
testbuffers.append( "\x00\x00")                       #       
testbuffers.append( "\xff\x25\xfc\xfc\x37\x08")       #       jmp    *0x837fcfc
testbuffers.append( "\xe9\xd0\xf3\xff\xff")           #       jmp    804c5b4
testbuffers.append( "\x68\x20\x06\x00\x00")           #       push   $0x620
testbuffers.append( "\x89\x44\x24\x14")               #       mov    %eax,0x14(%esp)
testbuffers.append( "\x8b\x42\x0c")                   #       mov    0xc(%edx),%eax
testbuffers.append( "\xe8\xf8\x03\x00\x00")           #       call   809ee70
testbuffers.append( "\xb8\x30\xc8\x2e\x08")           #       mov    $0x82ec830,%eax
testbuffers.append( "\x8b\x5d\xfc")                   #       mov    0xfffffffc(%ebp),%ebx
testbuffers.append( "\x89\x5d\xfc")                   #       mov    %ebx,0xfffffffc(%ebp)
testbuffers.append( "\x26\x26\x26\x26\x26\x26")       #       add    %ch,%es:(%eax)    (per PyDasm)
testbuffers.append( "\x69\x69\x69\x69\x69\x69")       #       imul $0x69696969,0x69(%ecx),%ebp


def getOperandValue(vtrace, op, operand):
    dereference = False
    add = ""
    numaddr = 0
    source = operand
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
        numaddr += (vtrace.getRegisterByName(reg) & mask)
        #print >>outfile,("DEBUG-reg: %x"%numaddr)
    elif isinstance(source, Address):
        numaddr += source.value
        if source.relative:
            numaddr += eip + op.off
        #print >>outfile,("DEBUG-addr: %x"%numaddr)
    if dereference:
        try:
            numaddr = struct.unpack("L",vtrace.readMemory(numaddr, 4))[0]
            #print >>outfile,("DEBUG-deref: %x"%numaddr)
        except:
            #print >>outfile,("DEBUG-deref-except: %x"%numaddr)
            #print >>stderr,("DEBUG-deref-except: %x"%numaddr)
            pass
            
    return numaddr


def disass(bytes, offset=0, VMA = 0, mode = 32, printbytes = True):
    """  This is just a simple interactive "byte" disassembler for real byte decoding, etc..."""
    for addr,opcode in disassLD(bytes, offset, VMA, mode):
        if printbytes:
            print "%x: %40s\t%s"%(addr,hexText(opcode.data[opcode.dataoffset:opcode.off]), opcode.printOpcode("AT&T", addr))
        else:
            print "%x: %s"%(addr,opcode.printOpcode("AT&T", addr))

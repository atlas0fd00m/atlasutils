import envi
import envi.archs.i386 as e_i386
import envi.archs.i386.opcode86 as i3op
import envi.archs.amd64 as e_amd64
import envi.archs.amd64.opcode86 as i64op



def asm(instr):
    pieces = instr.split()
    nmem = pieces.pop(0)

    prefix = []
    while mnem in (PREFIXES):
        prefix.append(mnem)
        nmem = pieces.pop(0)

    raise (Exception("Not completed."))

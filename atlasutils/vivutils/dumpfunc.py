
# vivisect script to dump a function to a .s file

def dumpFunc(vw, fva, filename):
    o = []
    
    funcva = vw.getFunction(fva)
    blocks = vw.getFunctionBlocks(funcva)
    for block in blocks:
        bva, sz, fnva = block
        eva = bva+sz
        va = bva
        while va < eva:
            op = vw.parseOpcode(va)
            print op
            o.append(str(op))
            va += len(op)
            
        outf = file(filename, 'w').write( '\n'.join(o) )

#FIXME: make a renderCanvas that changes addresses to locations and adds in labels
class textRenderer(MemoryRenderer):
    """
    chews up a VivWorkspace thing and spits out the text for it
    """

    def rendSymbol(self, mcanv, va):
        """
        If there is a symbolic name for the current va, print it...
        """
        sym = mcanv.syms.getSymByAddr(va)
        if sym != None:
            mcanv.addVaText("%s:\n" % repr(sym), va)

    def rendVa(self, mcanv, va):
        tag = mcanv.getVaTag(va)
        mcanv.addText("%.8x:" % va, tag=tag)

    def rendChars(self, mcanv, bytes):
        for b in bytes:
            val = ord(b)
            bstr = "%.2x" % val
            if val < 0x20 or val > 0x7e:
                b = "."
            mcanv.addNameText(b, bstr)

    def render(self, mcanv, va):
        """
        Render one "unit" and return the size you ate.
        mcanv will be a MemoryCanvas extender and va
        is the virtual address you are expected to render.
        """
        raise Exception("Implement render!")
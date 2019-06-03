
import vivisect
import atlasutils.hacklib as ahl

def findPivots(vw):
    if vw.arch._arch_name in ('amd64', 'i386'):
        pivotbytes = ahl.PIVOTBYTES_x86
    else:
        raise Exception("Architecture Pivot Bytes unknown for arch %s" % repr(vw.arch._arch_name))
    
    retval = []
    for needle in pivotbytes:
        for pivotva in vw.searchMemory(needle):
            retval.append((pivotva, vw.parseOpcode(pivotva)))
    return retval






def cleanVW(vw, filename=None):
    vw2 = vivisect.VivWorkspace()

    if filename == None:
        filename = vw.metadata['StorageName'].strip('.viv')

    vw2.loadFromFile(filename)
    vw2.analyze()
    
    #functions first
    newfuncvas = vw2.funcmeta.keys()
    for funcva in vw.funcmeta.keys():
        if funcva not in newfuncvas:
            vw2.makeFunction(funcva)

    #then codeblocks
    for cb in vw.codeblocks:
        if cb not in vw2.codeblocks:
            vw2.makeCode(cb)

    #then loclist:
    for loctup in vw.loclist:
        lva, lsize, ltype, linfo = loctup
        if loctup not in vw2.loclist:
            for nltidx in xrange(len(vw2.loclist)):
                nlt = vw2.loclist[nltidx]
                nva, nsize, ntype, ninfo = nlt
                if nva == lva:
                    vw2.loclist.pop(nltidx)
                    break

            vw2.addLocation(lva, lsize, ltype, linfo)
        
    #then va_by_name
    newvanames = vw2.va_by_name.keys()
    for vaname,va in vw.va_by_name.items():
        if vaname not in newvanames:
            vw2.makeName(va, vaname)

    #then bookmarks (vasets)

    return vw2

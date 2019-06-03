def doStrings(start, end, minbytes=4):
    print "%x -> %x" % (start, end)
    last = None
    va = start
    while va < end:
        ch = ord(vw.readMemory(va,1))
        if vw.xrefs_by_to.get(va) is not None or (9 <= ch <=0x7f):
            x = va + 1
            while x < end:
                #print "x: %x" % x
                ch = ord(vw.readMemory(x,1))
                if not (ch == 0 or 0x20 <= ch <=0x7e):
                    #print "nope %x" % va
                    break
                if vw.xrefs_by_to.get(x) is not None or ch == 0:
                    #if x-va > minbytes and :
                    vw.makeString(va)
                    #print ("-- %x - %x" % (va, x))
                    while x < end and vw.readMemory(x+1,1) == '\x00':
                        x += 1
                    va = x
                    break
                else:
                    x += 1
        va += 1
    print "done"


if 'vw' in globals().keys():
    start = int(argv[1],16)
    stop  = int(argv[2],16)
    doStrings(start, stop)

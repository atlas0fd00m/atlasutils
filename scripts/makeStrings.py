import logging
logger = logging.getLogger('vivscripts.makeStrings')

import string
printables = string.printable.encode('utf-8')

logger.warning("String Finder")
def main(argv):
    vw.vprint("String Finder")
    if len(argv) == 4:
        minsize = int(argv[3], 0)
    else:
        minsize = 3

    makeStrings(vw, int(argv[1], 0), int(argv[2], 0), minsize)
    vw.vprint("DONE.")


def makeStrings(vw, startva, endva, minsize=3):
    count = 0
    strlen = 0
    va = startva

    while va < endva:
        logger.warning('..va: 0x%x', va)
        loctup = vw.getLocation(va)
        if loctup is not None:
            logger.warning('...location exists: %r', loctup)
            lva, lsz, ltype, ltinfo = loctup
            va = lva + lsz
        
        elif vw.readMemory(va, 1) == b'\0':
            logger.warning('...skipping NULL byte')
            va += 1
            continue

        else:
            off = 0
            bad = False
            char = vw.readMemory(va + off, 1)

            logger.warning('...seeking NULL byte:')
            while char != b'\0':
                logger.warning('....offset: %d', off)
                if (va+off >= endva):
                    logger.warning("..... not found NULL before endva.")
                    bad = True
                    va += off + 1
                    break

                logger.warning('....char: %r', char)
                if char not in printables:
                    bad = True
                    va += off + 1
                    break

                off += 1
                char = vw.readMemory(va + off, 1)

            if bad:
                # find a good starting point again... or just bail?
                logger.warning("BAD string... bailing early cuz i'm lazy")
                va += off + 1
                while char != b'\0':
                    va += 1
                    char = vw.readMemory(va, 1)



            else:
                if off >= minsize:
                    vw.makeString(va)
                    count += 1
                    strlen += off
                va += off + 1

            # done 
    logger.warning("New Strings: %d  (%d bytes)", count, strlen)
    vw.vprint("New Strings: %d  (%d bytes)" % (count, strlen))



# only usable as a Vivisect script tool
if __name__ == 'builtins':
    print('\n'.join(globals().keys()))
    print(repr(argv))
    main(argv)

else:
    print(__name__)

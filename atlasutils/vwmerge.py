import logging
import vivisect
logging.basicConfig(level=logging.INFO)


def immerge(vw0, vw1, subs=None):
    if subs is None:
        subs = {}

    for filenm in vw1.getFiles():
        vw0.vprint("merging VW file: %r" % filenm)
        # do substitutions
        tgtfilenm = subs.get(filenm, filenm)

        if tgtfilenm in vw0.getFiles():
            vw0.vprint("    found!")
            vw0ib = vw0.getFileMeta(tgtfilenm, 'imagebase')
            vw1ib = vw1.getFileMeta(filenm, 'imagebase')    # what about multiples?  oh, file should be based correctly, we hope
            imgdelta = vw0ib - vw1ib
            vw0.vprint("(va delta: 0x%x)" % imgdelta)

            # do names first
            vw0.vprint("Merging Names...")
            for va1, name in vw1.name_by_va.items():
                rebaseva = va1 + imgdelta
                vw0.vprint("0x%x: %r   0x%x: %r" % (va1, name, rebaseva, vw0.getName(rebaseva)))
                if name.endswith("_%.8x" % va1):
                    name = name[:-9] + "_%.8x" % rebaseva
                vw0.vprint("=> 0x%x:  %r" % (rebaseva, name))

                curname = vw0.getName(rebaseva)
                if curname == name:
                    continue

                if curname is not None and curname != name and curname != "sub_%.8x" % rebaseva:
                    whichname = None
                    while whichname not in ('1', '2'):
                        whichname = input("0x%x:  (1) %r    (2) %r    choose: " % (rebaseva, curname, name))
                        vw0.vprint("your answer: %r" % whichname)

                    if whichname == '1':
                        continue

                vw0.makeName(rebaseva, name)

            # now roll through locations:
            #'LOC_STRUCT',
            # import any structure namespaces
            ct_struct = 0
            for lva, lsz, lt, lti in vw1.getLocations(vivisect.LOC_STRUCT):
                print("LOC_STRUCT: %r  %r", hex(lva), lti)
                ct_struct += 1

            #'LOC_PAD',
            # nahhhh, skip it.

            #'LOC_IMPORT',
            #  we may not want imports, if we've imported the whole memoryspace

            #'LOC_OP',
            # skip these... assume they're identified in makeFunction

            print('LOC_NUMBER')
            ct_num = 0
            for lva, lsz, lt, lti in vw1.getLocations(vivisect.LOC_NUMBER):
                #print("LOC_NUMBER", hex(lva), lsz, lti)
                tloc = vw0.getLocation(lva+imgdelta)
                if tloc is not None:
                    tlva, tlsz, tlt, tlti = tloc
                    if tlt != lt or tlti != lti:
                        vw0.vprint("number failure: 0x%x: %r %r" % (lva, repr((lva, lsz, lt, lti)), repr(tloc)))
                        continue
                vw0.makeNumber(lva + imgdelta, lsz)
                ct_num += 1

            print('LOC_POINTER')
            ct_ptr = 0
            for lva, lsz, lt, lti in vw1.getLocations(vivisect.LOC_POINTER):
                #print("LOC_POINTER", hex(lva), lti)
                if lti is not None:
                    lti += imgdelta
                tloc = vw0.getLocation(lva+imgdelta)
                if tloc is not None:
                    tlva, tlsz, tlt, tlti = tloc
                    if tlt != lt or tlti != lti:
                        input("pointer failure: 0x%x: %r %r" % (lva, repr((lva, lsz, lt, lti)), repr(tloc)))
                        continue

                if lti:
                    vw0.makePointer(lva + imgdelta, tova=lti)
                else:
                    vw0.makePointer(lva + imgdelta)
                ct_ptr += 1

            print('LOC_UNI')
            ct_uni = 0
            for lva, lsz, lt, lti in vw1.getLocations(vivisect.LOC_UNI):
                #print("LOC_UNI", hex(lva), lti)
                tloc = vw0.getLocation(lva+imgdelta)
                if tloc is not None:
                    tlva, tlsz, tlt, tlti = tloc
                    if tlt != lt or tlti != lti:
                        vw0.vprint("uni failure: 0x%x: %r %r" % (lva, repr((lva, lsz, lt, lti)), repr(tloc)))
                        continue
                vw0.makeUnicode(lva + imgdelta)
                ct_uni += 1

            print('LOC_STRING')
            ct_str = 0
            for lva, lsz, lt, lti in vw1.getLocations(vivisect.LOC_STRING):
                #print("LOC_STRING", hex(lva), lti)
                tloc = vw0.getLocation(lva+imgdelta)
                if tloc is not None:
                    tlva, tlsz, tlt, tlti = tloc
                    if tlt != lt or tlti != lti:
                        vw0.vprint("string failure: 0x%x: %r %r" % (lva, repr((lva, lsz, lt, lti)), repr(tloc)))
                        continue
                vw0.makeString(lva + imgdelta)
                ct_str += 1


            # make functions
            print('FUNCTIONS')
            ct_funcs = 0
            for fva in vw1.getFunctions():
                newfva = fva + imgdelta
                # do a few checks first
                loc = vw1.getLocation(fva)
                if loc is None:
                    continue
                lva, lsz, lt, lti = loc
                if lt != vivisect.LOC_OP:
                    continue
                # finally, grab the arch (useful for ARMv7)
                arch = lti
                vw0.makeFunction(newfva, arch=arch)
                ct_funcs += 1

            # should we do XREFS that aren't there yet???
            print('XREFS')
            ct_xrefs = 0
            for xref in vw1.getXrefs():
                xfr, xto, xt, xtflag = xref
                xfr += imgdelta
                xto += imgdelta
                skip = False
                for xr2 in vw0.getXrefsFrom(xfr):
                    if xr2 == (xfr, xto, xt, xtflag):
                        skip = True

                if skip:
                    continue

                vw0.addXref(xfr, xto, xt, xtflag)
                ct_xrefs += 1

            # VaSets?
            print('VaSets')
            for vaset in vw1.getVaSetNames():
                if vaset not in vw0.getVaSetNames():
                    defs = vw1.getVaSetDef(vaset)
                    vw0.addVaSet(vaset, defs)
                print("... %r" % vaset)
                for vasetrow in vw1.getVaSetRows(vaset):
                    newrow = (vasetrow[0] + imgdelta, ) + vasetrow[1:]
                    vw0.setVaSetRow(vaset, newrow)


            vw0.setFileMeta(tgtfilenm, 'merged', True)
        else:
            vw0.vprint("    not found...")

    vw0.vprint("DONE.")

if __name__ == "__main__":
    import sys
    dest = sys.argv[1]
    print("loading Destination Workspace: %r" % dest)
    vw0 = vivisect.VivWorkspace()
    vw0.loadWorkspace(dest)

    for srcidx in range(2, len(sys.argv)):
        src = sys.argv[srcidx]
        subs = None
        # check if we tagged this as a different name than what the file suggests
        if ':' in src:
            src, subs_str = src.split(':', 1)
            subs = {key: val for key, val in [keyval.split('=') for keyval in subs_str.split(',')]}

        vw1 = vivisect.VivWorkspace()
        print("loading import Workspace: %r" % src)
        vw1.loadWorkspace(src)

        if not input("Merge Metadata from %r  ==> into ==> %r? Type YES to confirm: " %(src, dest)) == "YES":
            print("Skipping.")
            continue

        print("Merging...")
        immerge(vw0, vw1, subs)
        vw0.vprint("Saving Workspace...")
        vw0.saveWorkspace()


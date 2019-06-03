'''
scan through xrefs looking for VFTables, labeling them appropriately
'''

# TODO: VFTables
# TODO: VF Naming and Correlation
# TODO: Static Classes

def analyze(vw):
    # identify VFTables
    # cycle through XREFs of type REF_PTR
    for xrfr, xrto, xrtype, xrflag in vw.getXrefs(REF_PTR):
        # make sure the target is a pointer (possibly having valid pointers after??  
        ptr = vw.readMemoryPtr(xrto)
        if not vw.isValidPointer(ptr): continue
        if not vw.isExecutable(ptr): continue
        if not vw.isProbablyCode(ptr): continue

        # check for XREFs to that location
            # none should be REF_CODE
            # should be from instructions like "push" and "lea" and "mov" (x86-specific.  ugh)
            # should be moved into a reg-deref like [esi] or [ecx] or [eax] in one of the instructions...  ?? 

    # label as VFTables

    # label Virtual Functions (that aren't already named)


if 'vw' in globals().keys():
    analyze(vw)


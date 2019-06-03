#!/usr/bin/python

from atlasutils.vtraceutils import *

"""
currently a toy.  Not for general consumption
"""


if len(argv) == 1:
    print ("Syntax:   $ %s <programpath>"%argv[0])
    exit(1)
    

            


class LibcallBreakpoint(Breakpoint):
    def __init__(self, libcall):
        Breakpoint.__init__(self, int(libcall.value))
        self.name = libcall.name
        self.stype = libcall.stype
        self.value = libcall.value
        self.fname = libcall.fname
    
    def notify(self, event, trace):
        #eip = trace.getProgramCounter()
        pid = trace.getMeta('ThreadId')
        esp = trace.getRegisterByName('esp')
        ret = trace.readMemoryFormat(esp, "L")[0]
        print("%x (t%d): call to %s:%s (%x)"%(ret, pid, self.fname, self.name, self.value))
        


class LibraryNotifier(vtrace.Notifier):
    """
    A small example notifier which prints
    out libraries as they are loaded.
    """
    def notify(self, event, trace):
        if event == vtrace.NOTIFY_LOAD_LIBRARY:
            lib = trace.getMeta("LatestLibrary")
            print "-----Library Loaded:",lib
            self.addBreaksForLib(trace, lib)

    def addBreaksForLib(self, me, lib):
        for sym in me.getSymsForFile(lib):
            if sym.stype == 2 and sym.value != 0:
                print ("setting breakpoint at %s:%s (%x)"%(lib, sym.name, sym.value))
                bp = LibcallBreakpoint(sym)
                me.addBreakpoint(bp)

bin = argv[1]
args = ""
if len(argv) > 2:
    args = " ".join(argv[2:])


me = getTrace()
libnotifier = LibraryNotifier()
me.execute("%s %s"%(bin,args))
me.registerNotifier(NOTIFY_LOAD_LIBRARY, libnotifier)


for lib in me.getNormalizedLibNames():
    libnotifier.addBreaksForLib(me, lib)


me.setMode("RunForever", True)

me.run()
# this is a vdb script and expects to have a trace object, etc...


bpid = trace.addBreakByExpr("libc.malloc", True)
trace.setBreakpointCode(bpid, "trace.setMeta('mallocstart', (poi(esp),poi(esp+4))); trace.runAgain()")
#        print 'MALLOC: ',hex(poi(esp+4)); trace.runAgain()")

bpid = trace.addBreakByExpr("libc.malloc+0xad", True)
trace.setBreakpointCode(bpid, "blah=trace.getMeta('mallocstart'); print( '%8x:  MALLOC(0x%x) -> %x' % (blah[0], blah[1], eax)) ;trace.runAgain()")

bpid = trace.addBreakByExpr("libc.free", True)
trace.setBreakpointCode(bpid, "print '%8x:  free(0x%x)   (size:%x)' % (poi(esp), poi(esp+4), poi(poi(esp+4)-4)&0xfffffffe) ; trace.runAgain()")


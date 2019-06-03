#!/usr/bin/env python
#####!/usr/bin/env python2.4

"""
regression tester for invisigoth's vtrace
"""

from atlasutils.vtraceutils import *
from sys import *
import select
import time

app='kcalc'

if len(argv) > 1:
    app=argv[1]
print >>stderr,("Starting Test of Visigoth's Vtrace against '%s' (assuming you have started %s)"%(app,app))
print >>stderr,("* Attaching to first instance of %s"%app)
me = atch(app)
me.registerNotifier(vtrace.NOTIFY_ALL, VerboseNotifier())


print >>stderr,("\n\n\n* stepi() (100 times fast)")
for i in range (100):
    me.stepi()
    
print >>stderr,("\n\n\n= setting NonBlocking to True")
me.setMode("NonBlocking", True)

print >>stderr,("* run()")
me.run()

print >>stderr,("     (sleep for 10 secs)")
select.select([],[],[],10)

print >>stderr,("* sendBreak()")
me.sendBreak()
select.select([],[],[],.5)
print(me)


while (me.getProgramCounter() > 0xf0000000):
    stepi(me)

for i in range(100):
    eip = me.getProgramCounter()
    if (eip < 0xf0000000):
        print >>stderr,("\n* addBreakpoint(DisplayBreaker(0x%x))"%eip)
        try:
            me.addBreakpoint(DisplayBreaker(eip))
            #me.addBreakpoint(Breakpoint(eip))
        except:
            a,b,c=exc_info()
            excepthook(a,b,c)
    me.stepi()

print >>stderr,("= setting RunForever to True")
me.setMode("RunForever", True)

print >>stderr,("* run()")
me.run()

print >>stderr,("     (sleep for 120 secs)")
select.select([],[],[],120)


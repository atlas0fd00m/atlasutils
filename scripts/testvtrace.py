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
print(("Starting Test of Visigoth's Vtrace against '%s' (assuming you have started %s)"%(app,app)), file=stderr)
print(("* Attaching to first instance of %s"%app), file=stderr)
me = atch(app)
me.registerNotifier(vtrace.NOTIFY_ALL, VerboseNotifier())


print(("\n\n\n* stepi() (100 times fast)"), file=stderr)
for i in range (100):
    me.stepi()
    
print(("\n\n\n= setting NonBlocking to True"), file=stderr)
me.setMode("NonBlocking", True)

print(("* run()"), file=stderr)
me.run()

print(("     (sleep for 10 secs)"), file=stderr)
select.select([],[],[],10)

print(("* sendBreak()"), file=stderr)
me.sendBreak()
select.select([],[],[],.5)
print(me)


while (me.getProgramCounter() > 0xf0000000):
    stepi(me)

for i in range(100):
    eip = me.getProgramCounter()
    if (eip < 0xf0000000):
        print(("\n* addBreakpoint(DisplayBreaker(0x%x))"%eip), file=stderr)
        try:
            me.addBreakpoint(DisplayBreaker(eip))
            #me.addBreakpoint(Breakpoint(eip))
        except:
            a,b,c=exc_info()
            excepthook(a,b,c)
    me.stepi()

print(("= setting RunForever to True"), file=stderr)
me.setMode("RunForever", True)

print(("* run()"), file=stderr)
me.run()

print(("     (sleep for 120 secs)"), file=stderr)
select.select([],[],[],120)


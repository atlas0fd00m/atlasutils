#!/usr/bin/ipython

import sys
import time
import vtrace
import vtrace.notifiers as vt_n
import atlasutils.vtraceutils as av

pattern = sys.argv[1]


s = vtrace.getTrace()
current = []

def calibrate():
	global current
	for pid,name in s.ps():
		if pattern in name and pid not in current:
			current.append(pid)

calibrate()

pid = None

def rotate(stopOnExc=False):
	while True:
	    wait()
            if go(stopOnExc): return

def go(stopOnExc=False):
    try:
	while True:
	    t.run()
	    if not t.isAttached(): break

            try:
	        print av.printStuff(t)
            except Exception, e:
                print e
	    
            #fixme: if exception in tracer, drop to interactive mode
            if t.metadata['PendingSignal'] != None and stopOnExc:
                print "Caught Signal, returning to interactive python (you did use -i or ipython, right?."
                return 1

    except KeyboardInterrupt:
	print "Caught Ctrl-C, returning to interactive python (if you ran it that way)."
        t.sendBreak()
        t.running = False
	return 1
    except:
	sys.excepthook(*sys.exc_info())
    return 0


def wait():
	global current, t, s, pattern, pid

	t = vtrace.getTrace()
	print("Current PIDs")
	print(repr(current))

	pid = None

	print "waiting for new child..."
	while pid==None:
		#print(repr(current))
		for ppid,name in s.ps():
			if ppid not in current and pattern in name:
				pid = ppid
				break

	time.sleep(.3)
	t.attach(pid)
        t.registerNotifier(vtrace.NOTIFY_ALL, vt_n.VerboseNotifier())
	t.sendBreak()
	print("Caught one.  Attaching to %d" % pid)


print "wait() or rotate()"


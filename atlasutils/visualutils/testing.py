from visual import *
import time



def setupSpheres(count=50):
    global ptsary,sphrs
    ptsary = []
    for x in range(count):
        for y in range(count):
            for z in range(count):
                ptsary.append((x,y,z))
    sphrs = [sphere(pos=x,color=vector(x)/count, size=1) for x in ptsary]


def setupPoints(count=50):
    global ptsary,pts
    ptsary = []
    colorary = []
    for x in range(count):
        for y in range(count):
            for z in range(count):
                ptsary.append((x,y,z))
                colorary.append((1.0*x/count,1.0*y/count,1.0*z/count))
    pts = points(pos=ptsary,color=colorary,size=10, size_units="world")

def testColorChangeSpheres(color):
    global sphrs
    start = time.time()
    for sphr in sphrs:
        sphr.color = color
    stop = time.time()
    return stop-start


def testColorChangePoints(color):
    global pts
    start = time.time()
    colors = pts.get_color()
    for cidx in xrange(len(colors)):
        colors[cidx] = color
    stop = time.time()
    return stop-start

#scene.stereodepth=2
#scene.stereo="redcyan"

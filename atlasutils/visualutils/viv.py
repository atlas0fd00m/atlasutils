import time
import vivisect

from visual import *

if locals().get('funcballs') == None:
    funcballs = None


def vizFuncs(vw, FACTOR = 10, diam=0.5, l=None,w=None,h=None):
    global floor, funcballs

    newobjects = False
    if funcballs == None:
        funcballs = {}
        newobjects = True

    funcvas = vw.getFunctions()
    funcvas.sort()
    count = len(funcvas)                    ; print "numFuncs: %d" % count

    height = sqrt(count) + 1                ; print "height:   %d" % height
    width = int(sqrt(height))               ; print "width:    %d" % width
    halfwidth = .5*width

    layersize = height                      ; print "layersz:  %d" % layersize


    if floor != None:
        floor = box (pos=(0,0,0), length=width*FACTOR, height=0.5, width=width*FACTOR, color=color.blue)

    for fidx in xrange(len(funcvas)):
        funcva = funcvas[fidx]
        y = (height - int(fidx / layersize)) * FACTOR   #FIXME: should be int() but we're going to play..
        l = (fidx % layersize)
        x = (int(l / width) - (halfwidth)) * FACTOR
        z = ((l % width) - halfwidth) * FACTOR

        if newobjects:
            fb = (sphere(pos=(x,y,z), length=diam, height=diam, width=diam, color=color.red))
            fb.label = label("fva: 0x%.8x" % funcva)
            funcballs[funcva] = fb

        else:
            fb = funcballs[funcva]
            fb.pos = (x,y,z)
            if l != None:
                fb.length = l
            if w != None:
                fb.width = w
            if h != None:
                fb.height = h

    return funcballs

def colorize():
    FACTOR = 1
    global floor, funcballs
    count = len(funcballs)                  ; print "numFuncs: %d" % count

    height = sqrt(count) + 1                ; print "height:   %d" % height
    width = int(sqrt(height))               ; print "width:    %d" % width
    halfwidth = .5*width

    layersize = width ** 2                  ; print "layersz:  %d" % layersize

    items = funcballs.items()
    items.sort()
    for fidx in xrange(len(items)):
        funcva, funcb = items[fidx]
        y = (height - (fidx / layersize)) * FACTOR   #FIXME: should be int() but we're going to play..
        l = (fidx % layersize)
        x = (int(l / width) - (halfwidth)) * FACTOR
        z = ((l % width) - halfwidth) * FACTOR

        cy = (1.0*abs(y/height))
        cx = (1.0*abs(x/halfwidth))
        cz = (1.0*abs(z/halfwidth))

        funcballs[funcva].color = vector(cx,cy,cz)

def cycle(balls, rad=4, color=color.green):
    global funcballs

    for fb in balls:
        oclr = fb.color
        orad = fb.radius
        fb.color = color
        fb.radius = rad
        #
        rate(300)
        fb.color = oclr
        fb.radius = orad


def mouseplay():
    while True:
        rate(100)
        if scene.mouse.events:
            event = scene.mouse.getevent()
            print repr(vars(event))
            mouse = scene.mouse.getclick()
            obj = mouse.pick
            #if mouse.
            if obj != None and obj.radius != None:
                print "radius = %f" % obj.radius
                obj.radius = (3,5,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1) [int(obj.radius)]
            #else:
            #    obj.radius = 2

def demo():
    floor = box (pos=(0,0,0), length=400, height=0.5, width=400, color=color.blue)
    ball = sphere (pos=(0,400,0), radius=1, color=color.red)
    ball.velocity = vector(0,-1,0)
    dt = 0.01

    while 1:
        rate (100)
        ball.pos = ball.pos + ball.velocity*dt
        if ball.y < ball.radius:
            ball.velocity.y = abs(ball.velocity.y)
        else:
            ball.velocity.y = ball.velocity.y - 9.8*dt





if __name__ == "__main__":
    demo()

import vivisect
if locals().get('vw') == None:
    vw = vivisect.VivWorkspace()
    vw.loadWorkspace('libxul.so.viv')

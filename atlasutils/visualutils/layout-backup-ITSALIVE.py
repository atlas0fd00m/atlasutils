import math
import time
import random
import vivisect
import threading

from visual import *

# rate constants
STABILITY_CONST =   2
VELOCITY_COEFF =    .1     # dampen the effects a little
SPEED_LIMIT =       10

# force constants
GRAVITY_COEFF =     .098
CENTER_PULL =       .05
FRICTION_COEFF =    .001

# log force constants  (these forces vary by distance)
NODE_FORCE_COEFF = 1
#NODE_FORCE_BASE =  math.e
EDGE_FORCE_COEFF = .11
EDGE_FORCE_BASE =  math.e


class Node(sphere):
    def __init__(self, system, ident, color=color.blue):
        x = random.randint(1, system.ceiling)
        y = system.ceiling
        z = random.randint(1, system.ceiling)
        pos = vector(x,y,z)
        sphere.__init__(self, pos=pos, radius=1)
        self.system = system
        self.edges = []
        self.ident = ident
        self.color = color

        self.velocity = vector(0,0,0)
        self.impulse = vector(0,0,0)

    def __sub__(self, other):
        return other.pos - self.pos 

    def isCollision(self, other):
        distance = self - other
        mindistance =  self.radius+other.radius
        if distance < mindistance:
            return True
        return False

    def move(self):
        # impose speed limit...
        if self.velocity.x > SPEED_LIMIT:
            self.velocity.x = SPEED_LIMIT
        elif self.velocity.x < -SPEED_LIMIT:
            self.velocity.x = -SPEED_LIMIT

        if self.velocity.y > SPEED_LIMIT:
            self.velocity.y = SPEED_LIMIT
        elif self.velocity.y < -SPEED_LIMIT:
            self.velocity.y = -SPEED_LIMIT

        if self.velocity.z > SPEED_LIMIT:
            self.velocity.z = SPEED_LIMIT
        elif self.velocity.z < -SPEED_LIMIT:
            self.velocity.z = -SPEED_LIMIT

        self.pos += self.velocity
        self.updateEdges()

    def updateEdges(self):
        for edge in self.edges:
            edge.updatePosition()

    def applyForces(self, coeff=1):
        raise(Exception("IMPLEMENT ME: applyForces"))

    def __repr__(self):
        return "Node: %x (%s)  pos=%s, vel=%s, force=%s, color=%s" % (self.ident, self.__class__.__name__, repr(self.pos), repr(self.velocity), repr(self.impulse), repr(self.color) )




class Edge(cylinder):
    def __init__(self, nodepairtup):
        n1,n2 = nodepairtup
        cylinder.__init__(self, pos=n1.pos, axis=(n2.pos-n1.pos), radius=.1)

        self.nodes = nodepairtup
        for node in nodepairtup:
            node.edges.append(self)

        print >>sys.stderr,("===== NEW EDGE CREATION ===== %s %s" % (nodepairtup))
        self.updatePosition()

    def updatePosition(self):
        n1,n2 = self.nodes
        self.pos=n1.pos
        self.axis=(n2.pos-n1.pos)

    def __repr__(self):
        n1,n2 = self.nodes
        return "".join([ "edge:", hex(n1.ident),"<->", hex(n2.ident), "  ", repr(self.pos), "/", repr(self.axis) ])

class System:
    def __init__(self):
        self.floor = box (pos=(0,0,0), length=400, height=0.5, width=400, color=(.05,.001,.3))
        self.nodes = {}
        self.edges = {}
        self.ceiling = 100      # FIXME: try having ceiling be the number of nodes
        self.smallest = 0xfffffffffffffffff
        self.minimum_safe_distance = 1
        self.time_on = True
        self.thread = threading.Thread(target=self.run)
        self.thread.setDaemon(True)
        self.thread.start()

    def go(self):
        self.time_on = True

    def stop(self):
        self.time_on = False

    def addNode(self, node):
        self.nodes[node.ident] = node
        if node.ident < self.smallest:
            self.smallest = node.ident

        #self.adjust()

    def addEdge(self, node1, node2, cls=Edge):
        edge = cls((node1, node2))
        if self.edges.get(edge.nodes) != None:
            raise(Exception("FAIL!  this node exists: %s" % repr(edge)))

        print >>sys.stderr,("adding new edge: %s" % repr(edge))

        self.edges[edge.nodes] = edge
        #self.adjust()

    def adjust(self):
        #go = True
        print >>sys.stderr,("adjusting system.")
        #pendulum = .99
        #while go:
        #adjustment = vector(0,0,0)
        adjustment = 0

        for node in self.nodes.values():
            print >>sys.stderr, node
            diff = node.applyForces()  # pendulum)
            adjustment += abs(diff)

        #x,y,z = adjustment
        #value = x+y+z
        #value = adjustment
        #if abs(value) <= STABILITY_CONST:
        #    go = False
        #else:
        #    print >>sys.stderr,("adjusting system.  adjustment = %s" % repr(value))
        #    #sys.stdin.readline()
        #pendulum *= .99      # let's see how it does without this dampener

    def run(self):
        while True:
            while self.time_on:
                self.adjust()
                for node in self.nodes.values():
                    node.move()
                time.sleep(.1)
            time.sleep(.1)



class VivNode(Node):
    def applyForces(self, coeff=1):
        s = self.system

        # next add up the forces acting on this node.  this is applied to velocity later.
        force = vector(0,0,0)

        # gravity pulling me toward base
        force.y -= GRAVITY_COEFF

        # just a little tug toward the center of the graph, to keep things from exploding
        force.x -= CENTER_PULL * self.x
        force.z -= CENTER_PULL * self.z

        # all my edges pulling me in a direction
        for e in self.edges:        # FIXME: this has to be broken...
            n1, n2 = e.nodes
            if (n1 == self):
                diff = n1 - n2
                n = n2
            else:
                diff = n2 - n1
                n = n1
            if not abs(diff):
                diff = vector(.0001, 0, .0001)

            f_dir = diff
            f_str = EDGE_FORCE_COEFF * ( 1 + math.log(abs(diff), EDGE_FORCE_BASE) )
            thisforce = ( f_dir * f_str )
            #thisforce = - ( EDGE_SPRING_COEFF * diff * (log( abs(diff) ) + 1) )
            print >>sys.stderr,("  EDGE: %x to %x:  diff=%s, absdiff=%s, dir=%s, str=%s, force=%s" % (self.ident, n.ident, diff, abs(diff), f_dir, f_str, thisforce))
            force += (thisforce * coeff)


        # all the other nodes pushing me away
        for n in s.nodes.values():
            if n == self:
                continue
            diff = (self - n)
            if not abs(diff):
                diff = vector(.0001, 0, .0001)

            f_dir = diff
            f_str = NODE_FORCE_COEFF / abs(diff)
            thisforce = - ( f_dir * f_str )
            #thisforce = NODE_FORCE_COEFF * diff / abs(diff)
            print >>sys.stderr,("  NODE: %x to %x:  npos=%s, diff=%s  abs(diff)=%s thisforce=%s dir=%s, str=%s velocity=%s" % 
                    (self.ident, n.ident, n.pos, diff, abs(diff), thisforce, f_dir, f_str, self.velocity))
            force += (thisforce * coeff)

            # bump-effect  (what happens if the other node comes into my space!?)
            if self.isCollision(n):
                m1 = self.radius * self.velocity
                m2 = n.radius * n.velocity
                # FIXME: finish momentum stuff here


        # bouncing off the floor
        if self.y <= s.minimum_safe_distance:
            self.y = s.minimum_safe_distance
            #self.velocity.y = -self.velocity.y
            # ok, enough bouncing....
            self.velocity.y = 0
        # ceiling
        if self.y > s.ceiling:
            self.y = s.ceiling
            #self.velocity.y = -self.velocity.y
            # ok, enough bouncing....
            self.velocity.y = 0

        # friction (yes, in free-fall in the air...  sue me
        force += FRICTION_COEFF *  -( self.velocity )
        
        
        # update my velocity based on force
        self.velocity += VELOCITY_COEFF * force

        # now, the one glued to the ceiling
        if s.smallest == self.ident:
            self.pos = vector(0, s.ceiling, 0)
            self.velocity = vector(0,0,0)
            force.y = 0         # FIXME: how will this work???  should we spell this out?

        return force

        


def test(system):
    for x in xrange(0x8048000, 0x8058000, 0x1000):
        n = VivNode(system, x)
        system.addNode(n)
        if len(system.nodes) > 1:
            nn = system.nodes.values()[-2]
            if n != nn:
                system.addEdge(n, nn)
        #
        if ((x>>8) % 4 == 3):
            nn = system.nodes.values()[-3]
            if n != nn:
                system.addEdge(n, nn)


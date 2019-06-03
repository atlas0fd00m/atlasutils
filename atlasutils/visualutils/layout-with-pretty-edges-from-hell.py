import time
import random
import vivisect

from visual import *

STABILITY_CONST =   2
GRAVITY_COEFF =     .01
NODE_FORCE_COEFF =  .3
EDGE_SPRING_COEFF = .5


class Node(sphere):
    def __init__(self, system, ident, color=color.blue):
        x = random.randint(1, system.ceiling)
        y = random.randint(1, system.ceiling)
        z = random.randint(1, system.ceiling)
        pos = vector(x,y,z)
        sphere.__init__(self, pos=pos, radius=1)
        self.system = system
        self.edges = []
        self.ident = ident
        self.color = color

    def updateEdges(self):
        for edge in self.edges:
            edge.updatePosition()

    def applyGravity(self):
        raise(Exception("IMPLEMENT ME: applyGravity"))

    def applyForces(self, coeff=1):
        raise(Exception("IMPLEMENT ME: applyForces"))

    def __repr__(self):
        return "  ".join([repr(self.__class__.__name__), hex(self.ident), repr(self.pos), repr(self.color) ])




class Edge(cylinder):
    def __init__(self, nodepairtup):
        self.nodes = nodepairtup
        for node in nodepairtup:
            node.edges.append(self)
        self.updatePosition()

    def updatePosition(self):
        n1,n2 = self.nodes
        cylinder.__init__(self, pos=n1.pos, axis=(n2.pos-n1.pos), radius=.1)

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

    def addNode(self, node):
        self.nodes[node.ident] = node
        if node.ident < self.smallest:
            self.smallest = node.ident

        self.adjust()

    def addEdge(self, node1, node2, cls=Edge):
        edge = cls((node1, node2))
        self.edges[edge.nodes] = edge
        self.adjust()

    def adjust(self):
        go = True
        print >>sys.stderr,("adjusting system.")
        pendulum = .99
        while go:
            adjustment = vector(0,0,0)

            for node in self.nodes.values():
                diff = node.applyForces(pendulum)
                adjustment += diff

                print >>sys.stderr, node


            x,y,z = adjustment
            value = x+y+z
            if abs(value) <= STABILITY_CONST:
                go = False
            else:
                print >>sys.stderr,("adjusting system.  adjustment = %s" % repr(value))
                sys.stdin.readline()
            pendulum *= .99

class VivNode(Node):
    def applyForces(self, coeff=1):
        s = self.system
        want = vector(0,0,0)

        # all the other nodes
        for n in s.nodes.values():
            if n == self:
                continue
            diff = (n.pos - self.pos)
            if not abs(diff):
                diff = vector(.0001, 0, .0001)
            thisforce = NODE_FORCE_COEFF * diff / abs(diff)
            print >>sys.stderr,("NODE: %x to %x:  force=%s  diff=%s  abs()=%s" % 
                    (self.ident, n.ident, thisforce, diff, abs(diff)))
            want += (thisforce * coeff)



        # all my edges
        for e in self.edges:        # FIXME: this has to be broken...
            if (e.nodes[0] == self):
                diff = -e.axis
            else:
                diff = e.axis
            if not abs(diff):
                diff = vector(.0001, 0, .0001)
            thisforce = -(EDGE_SPRING_COEFF * diff / abs(diff))
            print >>sys.stderr,("EDGE: %x to %x:  force=%s" % (self.ident, n.ident, thisforce))
            want += (thisforce * coeff)


        # gravity
        want.y -= GRAVITY_COEFF * (self.ident/s.smallest)        # FIXME: perhaps we don't need to multiply by ident?

        # the one glued to the ceiling
        if s.smallest == self.ident:
            want.y = s.ceiling - self.y
            want.x = -self.x
            want.z = -self.z



        # update self...
        self.pos += want

        # the floor
        if self.y <= s.minimum_safe_distance:
            self.y = s.minimum_safe_distance
            #want.y = 100        # FIXME: do we really want this to invalidate the graph?
        # ceiling
        if self.y > s.ceiling:
            self.y = s.ceiling
        

        self.updateEdges()

        return want

        


def test(system):
    for x in xrange(0x8048000, 0x8058000, 0x100):
        n = VivNode(system, x)
        system.addNode(n)
        if len(system.nodes) > 1:
            system.addEdge(n, system.nodes.values()[-2])
        #
        if ((x>>8) % 4 == 3):
            system.addEdge(n, system.nodes.values()[-3])


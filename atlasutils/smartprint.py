import sys

TEXTMIN = '\x20'
TEXTMAX = '\x7e'
IGNOREBIN = '\x09\x0a\x0d\x00'

def checkDATA(bytes, COEFF = 4):
        text = 0
        binary = 0
        for c in bytes:
                if (c >= TEXTMIN and c <= TEXTMAX):
                        text += 1
                else:
                        if (not c in IGNOREBIN):
                            binary += 1
        if ((text) > (COEFF * binary)):
                return True
        return False

def hexText(bytes):
        """
        hexText accepts a string and returns a HEX-ified version of it.
        """
        out = ""
        for ch in bytes:
                out += "\\x%.02x"%(ord(ch))
        return out

def SmartOutput(string, TEXTCOEFF=4):
        if (not checkDATA(string, TEXTCOEFF)):
                string = hexText(string)
        return string

def SmartPrint(string, COEFF=4):
	print(SmartOutput(string, COEFF))


def dumpTree(subtree, title="TREE:", outf = sys.stdout, ignore=(), deep=False, cb=None):
    """ 
    dumpTree() is a recursive sub which walks a tree-like data structure and ouputs the findings to the file of your choice
    stdout is the default output file, however, it could easily be used thus:
        dumpTree(mystrucureobject, "WEIRDO TREE", outf = file("dumptree.out","w"))
    """
    if (type(subtree) == list or type(subtree) == tuple):
        print >>outf,("%s: (%s)"%(title,type(subtree)))
        for item in range(len(subtree)):
            dumpTree(subtree[item], "%s:[%d]"%(title,item), outf, ignore)

    elif (type(subtree) == dict):
        print >>outf,("%s: (%s)"%(title,type(subtree)))
        for i in (subtree).keys():
            istr = repr(i)
            if istr in ignore:
                continue
            item = (subtree).get(i)
            dumpTree(item, "%s:%s"%(title,istr), outf, ignore)

    elif (repr(type(subtree)) == "<type 'instance'>"):
        print >>outf,("%s: (%s)"%(title,type(subtree)))
        if cb:
            cb(title, subtree)

        stvars = vars(subtree)
        for i in stvars.keys():
            istr = repr(i)
            if i in ignore:
                continue
            item = stvars.get(i)
            dumpTree(item, "%s:%s"%(title, istr), outf, ignore)

        if deep:
            for item in dir(subtree):
                istr = repr(item)
                if item in ignore:
                    continue
                dumpTree(item, "%s:%s"%(title, istr), outf, ignore)

    else:
        if (type(subtree) == str and len(subtree)>40):
            print >>outf,("%s %s == %s ..... (size = %d bytes)"%(title, type(subtree), subtree[:40], len(subtree)))
        elif (type(subtree) == int):
            print >>outf,("%s %s == 0x%x "%(title, type(subtree), subtree))
        else:
            print >>outf,("%s %s == %s "%(title, type(subtree), subtree))

"""
>>> for i in \
... vars(pe).keys():
...   print i
...   type(vars(pe).get(i))

"""

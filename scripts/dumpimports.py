import os
import sys
import vivisect
import atlasutils.smartprint as asp
from IPython.display import display

dependencies = {}


def scanDirectory(dirpath, recurse=True):
    names = os.listdir(dirpath)
    for name in names:
        fname = os.sep.join([dirpath,name])
        if os.path.isfile(fname):
            dumpImports(fname)

        elif os.path.isdir(fname) and recurse:
            scanDirectory(fname)

def dumpImports(filename):
    vw = vivisect.VivWorkspace()
    try:
        vw.loadFromFile(filename)
    except:
        print "%s not known executable format" % filename
        return

    try:
        display(vw.filemeta)
        imports = vw.getImports()
        display(imports)

        for lva, lsz, ltp, name in imports:
            libsplit = name.split('.',1)
            if len(libsplit) == 1:
                print("IMPORT WITHOUT LIBRARY: %s" % name)
                lib = "unknown"
                sym = name
            else:
                lib, sym = libsplit

            symlist = dependencies.get(lib)
            if symlist == None:
                symlist = {}
                dependencies[lib] = symlist

            symentry = symlist.get(sym)
            if symentry == None:
                symentry = {}
                symlist[sym] = symentry

            symentry[filename] = symentry.get(filename, 0) + 1

    except Exception, e:
        print e



def main(argv):
    for dirname in argv[1:]:
        scanDirectory(dirname)

if __name__ == '__main__':
    main(sys.argv)

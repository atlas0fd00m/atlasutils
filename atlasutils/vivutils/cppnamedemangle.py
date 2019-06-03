import os
import re
import sys
import string
import cxxfilt
import inspect
import subprocess
import ctypes.util as cutil
from ctypes import *

from vivisect import L_LTYPE, LOC_IMPORT

lib = cutil.find_library("stdc++")

def convertGCC_old(mangled):
    print "converting:  ", mangled
    libstdc = CDLL(lib)
    mbuf = c_buffer(mangled, 1000)
    status = c_int(0)
    nptr = libstdc.__cxa_demangle(mbuf, None, None, byref(status))

    if status.value != 0:
        print "Error: status: %s" % status

    name = c_char_p(nptr)
    if name.value != None:
        return name.value


vccpath = None
if globals().get('argv'):
    curdir = os.path.dirname(os.path.abspath(argv[0]))
else:
    curdir = os.path.dirname(os.path.abspath(sys.argv[0]))
print curdir


VCFILT = os.path.join(curdir, 'vc++filt.exe')
def convertVCPP(mangled):
    if not ("@" in mangled or "?" in mangled): return
    p = subprocess.Popen(VCFILT, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    p.stdin.write("%s\n" % mangled)
    p.stdin.close()
    newname = p.stdout.read().strip()
    print newname
    if newname != mangled:
        return newname
''' stolen from:    http://stackoverflow.com/questions/6526500/c-name-mangling-library-for-python

def demangle(names):
    args = ['c++filt']
    args.extend(names)
    pipe = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, _ = pipe.communicate()
    demangled = stdout.split("\n")

    # Each line ends with a newline, so the final entry of the split output
    # will always be ''.
    assert len(demangled) == len(names)+1
    return demangled[:-1]

print demangle(['_ZNSt15basic_stringbufIcSt11char_traitsIcESaIcEE17_M_stringbuf_initESt13_Ios_Openmode',
    '_ZNSt15basic_stringbufIcSt11char_traitsIcESaIcEE6setbufEPci'])
'''

def demangle(va, vaname, filefmt, files=[]):
    if not (vaname.startswith('_Z') or '._Z' in vaname):
        return None

    prefix = ''
    suffix = ''
    modname = ''
    args = None
    idx_ = vaname.rfind('_')    # lose the _08048999 address suffix
    if re.match('_[0-9a-f]{1,16}$', vaname[idx_:]) == None:
        workname = vaname
        suffix = '_%.8x' % va
    else:
        workname = vaname
        while re.match('_[0-9a-f]{1,16}$', workname[idx_:]) != None:
            suffix = vaname[idx_:] + suffix
            workname = vaname[:idx_]
            #print workname, suffix
            idx_ = workname.rfind('_')    # lose the _08048999 address suffix


    for vwnm in files:
        if vwnm.find('\\') > -1:
            vwnm = vwnm.split('\\')[-1]
        if vwnm.find('/') > -1:
            vwnm = vwnm.split('/')[-1]

        #print 'checking: ', vwnm
        stub = vwnm + "."
        if workname.startswith(stub):
            #print "w/stub:  ", workname
            workname = workname[len(stub):]
            prefix = stub + '.'
            break
        elif workname.startswith('*.'):
            #print "w/*.:  ", workname
            workname = workname[2:]
            prefix = "*."
            break

    # split between GCC and VC++
    newname = None
    try:
        if filefmt == 'pe':
            newname = convertVCPP(workname)

        if filefmt == "elf":
            # take care of the "@@GLIBCXX_3.4" and "@@CXXABI*" nonsense
            idxAT = workname.rfind('@@')
            if idxAT > -1 and re.match('@@[A-Z_0-9]', workname[idxAT:]):
                #print "slicing suffix at %d" % idxAT
                suffix += workname[idxAT:]
                workname = workname[:idxAT]
                
            parts = workname.rsplit('.', 1)
            if len(parts) > 1:
                modname, workname = parts

            #newname = convertGCC(workname)
            newname = modname + '.' + cxxfilt.demangle(workname)
            #print "%r -> %r" % (workname, newname)

    except Exception, e:
        print "error demangling (%r): %r" % (workname, e)
    finally:
        return prefix, newname, suffix




def analyze(vw, vwnm=None, normalize=False):
    if lib == None:
        return

    if vwnm == None:
        vwnm = vw.metadata['StorageName'].strip('.viv').replace('-', '_')

    importdict = {}
    for imp in vw.getImports():
        basename = imp[3].split('.')[0]
        importdict[basename] = True

    files = importdict.keys()
    files.append(vwnm)

    filefmt = vw.getMeta('Format')

    for va, vaname in vw.name_by_va.items():

        nametup = demangle(va, vaname, filefmt, files)

        if nametup == None:
            continue

        prefix, newname, suffix = nametup
        if newname == None:
            continue

        # if updates were made, make them so...
        # parse out the () args
        fname = newname
        bidx = newname.find('(')
        if bidx != -1:
            eidx = newname.find(')', bidx)
            if eidx != -1:
                args = newname[bidx+1:eidx]
                fname = newname[:bidx] + newname[eidx+1:]

        fname = prefix + normFuncName(fname + suffix)
        vw.vprint("=== updating %s -> %s" % (vaname, fname))
        try:
            vw.makeName(va, str(fname))
            vw.setComment(va, newname)
            if args != None:
                print "FIXME: update Function Args/Prototype"

            loc = vw.getLocation(va)
            if loc != None and loc[L_LTYPE] == LOC_IMPORT:
                print "WTF is this?  LOC_IMPORT... but handler is f'd"
                vw.addLocation(*loc[:3], tinfo=fname)

        except:
            sys.excepthook(*sys.exc_info())


    # update import/export tables:
    #for imp in vw.getImports():


    vw.vprint("DONE")


def normFuncName(funcname):
    out = []
    normname = os.path.basename(funcname)

    ok = string.letters + string.digits + '_'# + ':'# + '~'
    cok = ("%$#*<>~")

    lastcok = False
    chars = list(normname)
    for i in xrange(len(chars)):
        if chars[i] not in ok:
            if chars[i] in cok:
                x = "%.2X" % ord(chars[i])
                out.append(x)
                if not lastcok:
                    # prepend on front
                    out.insert(i, '_')

                lastcok = True

            else:
                out.append('_')
                lastcok = False

        else:
            if lastcok:
                # if last was a 'cok' and this is just ok...
                out.append('_')
            out.append(chars[i])

            lastcok = False

    normname = ''.join(out)
    #if normname[0].isdigit():
        #normname = '_' + normname

    return normname

def vivDemangleOne(vw):
    try:
        name = cxxfilt.demangle(name)
    except Exception, e:
        vw.vprint('Error demangling %r: %r' % (name, e))
        return

    vw.vprint('Name: %r' % name)

if 'vw' in globals().keys():
    analyze(vw)

elif __name__ == '__main__':
    import vivisect
    vw = vivisect.VivWorkspace()
    vw.loadWorkspace(sys.argv[1])
    analyze(vw)
    vw.saveWorkspace()


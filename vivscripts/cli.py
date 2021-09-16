'''
vivisect script (`script /path/to/this.py`)
'''
import envi.interactive as ei
import atlasutils.emutils as aemu
try:
    emu = vw.getEmulator()
    temu = aemu.TestEmulator(emu, verbose=True, fakePEB=True, guiFuncGraphName='FuncGraph0')

    if len(argv) > 1:
        codeva = vw.parseExpression(argv[1])
        emu.setProgramCounter(codeva)

except Exception as e:
    print(e)

STYPE_NONE = 0
STYPE_IPYTHON = 1
STYPE_CODE_INTERACT = 2

def interact(lcls, gbls, intro=""):
    shelltype = STYPE_NONE
    try:
        import IPython.Shell
        ipsh = IPython.Shell.IPShell(argv=[''], user_ns=lcls, user_global_ns=gbls)
        print(intro)
        shelltype = STYPE_IPYTHON

    except ImportError as e:
        try:
            from IPython.terminal.interactiveshell import TerminalInteractiveShell
            ipsh = TerminalInteractiveShell()
            ipsh.user_global_ns.update(gbls)
            ipsh.user_global_ns.update(lcls)
            ipsh.autocall = 2       # don't require parenthesis around *everything*.  be smart!
            shelltype = STYPE_IPYTHON
            print(intro)

        except ImportError as e:
            try:
                from IPython.frontend.terminal.interactiveshell import TerminalInteractiveShell
                ipsh = TerminalInteractiveShell()
                ipsh.user_global_ns.update(gbls)
                ipsh.user_global_ns.update(lcls)
                ipsh.autocall = 2       # don't require parenthesis around *everything*.  be smart!
                shelltype = STYPE_IPYTHON

                print(intro)
            except ImportError as e:
                print(e)
                shell = code.InteractiveConsole(gbls)
                shelltype = STYPE_IPYTHON
                print(intro)

    if shelltype == STYPE_IPYTHON:
        ipsh.mainloop()

    elif shelltype == STYPE_CODE_INTERACT:
        shell.interact()

    else:
        print("SORRY, NO INTERACTIVE OPTIONS AVAILABLE!!  wtfo?")

interact(locals(), globals())


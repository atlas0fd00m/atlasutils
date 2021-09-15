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

ei.dbg_interact(locals(), globals())


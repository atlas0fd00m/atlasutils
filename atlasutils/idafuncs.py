from idautils import *
from idaapi import *

ea = BeginEA()

symbols = {}
for funcea in Functions(SegStart(ea), SegEnd(ea)):
    functionName = GetFunctionName(funcea)
    functionStart = "0x%08x"%funcea
    functionEnd = "0x%08x"%FindFuncEnd(funcea)
    #print("%s : %s" % (functionName, functionStart))
    symbols[functionStart] = functionName


import pickle
pickle.dump(symbols, file('exportsyms.pickle', 'w'))

#print("%s : %s" % (functionName, functionStart))

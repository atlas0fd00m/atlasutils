from vstruct.primitives import *
import vstruct

PTRFMT = '<I'
PTRSIZE = 4
ALIGNSIZE = 4

# Vstruct classes
class VpdbHdr (vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.hdrString      = v_zstr(align=ALIGNSIZE)
        self.pageSize       = v_uint32()
        self.unk0           = v_uint32()
        self.pageCount      = v_uint32()
        self.totalStreamSize= v_uint32()
        self.unk1           = v_uint32()
        self.streamDir      = v_uint32()

class VpdbStreamDirMeta (vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.streamCount    = v_uint32()
        self.streamSizeArray= VArray([])


# parser class(es)
class PDB:
    def parse(self, datastream):
        self.datastream = datastream
        
    def parseHeader(self):
        #idx = 0
        #while idx<len(self.datastream) and self.datastream[idx] != '\x1a':
            #idx += 1
        #self.hdrStringEnd = idx
        
        #idx += 1
        ## skip the signature as well
        #while idx<len(self.datastream) and self.datastream[idx] != '\x00':
            #idx += 1
        #self.hdrSigEnd = idx
        
        ## true off to the next dword boundary
        #idx += (ALIGNSIZE - (idx % ALIGNSIZE) )
        
        # now parse the data fields
        self.hdrInfo = VpdbHdr()
        self.hdrInfo.vsParse(self.datastream[idx+1:])
        
    def getHdrSig(self):
        return self.datastream[self.hdrStringEnd: self.hdrSigEnd]
    
    def getStreamDirDataRaw(self):
        out = []
        pgsize = self.hdrInfo.pageSize
        
        # parse through the data directory allocation table
        idx = self.hdrInfo.streamDir * pgsize
        ptr = self.datastream[ idx : idx+PTRSIZE ]
        EOS = '\x00'* PTRSIZE
        while ptr != EOS:
            page, = struct.unpack(PTRFMT, ptr)
            data = self.datastream[ page*pgsize : (page+1)*pgsize ]
            out.append(data)
            
        return ''.join(out)
    
    def getStreamDirData(self):
        pass
        
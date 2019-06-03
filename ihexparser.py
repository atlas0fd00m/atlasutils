#!/usr/bin/python

import sys
import struct
MAX_MEMORY = 2 * 1024 * 1024

secnames = [
    "Data",
    "EOF",
    "Start Segment Address",
    "Extended Linear Address",
    "Start Linear Address",
    ]

""" from Wikipedia (http://en.wikipedia.org/wiki/Intel_hex)
There are six record types:
00, data record, contains data and 16-bit address. The format described above.
01, End Of File record, a file termination record. No data. Has to be the last line of the file, only one per file permitted. Usually ':00000001FF'.
02, Extended Segment Address Record, segment-base address. Used when 16 bits are not enough, identical to 80x86 real mode addressing. The address specified by the 02 record is multiplied by 16 (shifted 4 bits left) and added to the subsequent 00 record addresses. This allows addressing of up to a megabyte of address space. The address field of this record has to be 0000, the byte count is 02 (the segment is 16-bit). The least significant hex digit of the segment address is always 0.
03, Start Segment Address Record. For 80x86 processors, it specifies the initial content of the CS:IP registers. The address field is 0000, the byte count is 04, the first two bytes are the CS value, the latter two are the IP value.
04, Extended Linear Address Record, allowing for fully 32 bit addressing. The address field is 0000, the byte count is 02. The two data bytes represent the upper 16 bits of the 32 bit address, when combined with the address of the 00 type record.
05, Start Linear Address Record. The address field is 0000, the byte count is 04. The 4 data bytes represent the 32-bit value loaded into the EIP register of the 80386 and higher CPU.
To confuse the matter, there are various format subtypes:
I8HEX or INTEL 8, 8-bit format.
I16HEX or INTEL 16, 16-bit format. Allows usage of 02 records. The data field endianness may be byte-swapped.
I32HEX or INTEL 32, 32-bit format. Allows usage of 03, 04, and 05 records. The data field endianness may be byte-swapped.
Beware of byte-swapped data. Some programmers tend to misinterpret the byte order in case of I16HEX and I32HEX.


##### atlas: if anyone has bins that fail to load correctly, please email them to me at atlas@r4780y.com so I can improve this. #####
"""
class ihexbin:
    def __init__(self, bytes=None, sections=[], startaddress=None, chksm_errors=None, syntax_errors=None, memory_errors=None, bytecount_errors=None, offbyone_errors=None):
        self.bytes = bytes
        self.sections = sections
        self.startaddress = startaddress
        self.chksm_errors = chksm_errors
        self.syntax_errors = syntax_errors
        self.memory_errors = memory_errors
        self.bytecount_errors = bytecount_errors
        self.length = 0

        if bytes != None:
            self.ihex_load(bytes)

        for sec in self.sections:
            self.length += len(sec[2])

    def ihex_gen(self, linesize = 32):
        outstring = []
        address = self.startaddress
        for sec in self.sections:
            secsize = len(sec[2])
            secoffset = 0
            if (sec[0] > address):
                address = sec[0]
            
            if (secsize == 0 and sec[1] == 1):
                outstring.append(":00000001FF")
            while secoffset < secsize:
                bytestoprocess = linesize
                newline = ""
                if (secsize - secoffset < linesize):
                    bytestoprocess = secsize - secoffset
                for x in xrange(bytestoprocess):
                    newline += "%.2X"%(ord(sec[2][x+secoffset]))
                newline = ("%.2X%.4X%.2X%s"%(bytestoprocess, address, sec[1], newline))
                chksm = (calculate_checksum(newline))
                outstring.append(":%s%.2X"%(newline, chksm))
                
                address += bytestoprocess
                secoffset += bytestoprocess
                #print ("%x:%x"%(secoffset,secsize))
        return outstring

    def ihex_save(self, outf=sys.stdout, linesize = 32):
        for line in self.ihex_gen(linesize):
            print >>outf,(line)

    def data_gen(self):
        address = self.startaddress
        output = ""
        for sec in self.sections:
            if (address < sec[0]):
                diff = sec[0]-address
            output += sec[2]
            address += len(sec[2])
        return output

    def data_gen2(self):
        address = self.startaddress
        output = ""
        for sec in self.sections:
            if (address < sec[0]):
                diff = sec[0]-address
            output += sec[2]
            address += len(sec[2])
        return output


    def bin_gen(self):
        address = self.startaddress
        output = ""
        for sec in self.sections:
            if (address < sec[0]):
                diff = sec[0]-address
                output += "\x00"*(diff)
            output += sec[2]
            address += len(sec[2])
        return output
            
    def hexdump_save(self, LINESIZE=16, outfile = sys.stdout, skipsamelines = True, printText = True):
        """ from this style:
00000020  00 02 80 04 f7 09 d8 fc  78 22 90 10 e3 7a 04 ba  |........x"...z..|
        """
        output = ""
        input = buffer(self.bin_gen())
        inplen = len(input)
        address = 0
        lastline = ""
        while (address < inplen):
            same=False
            if skipsamelines and (inplen >= address+LINESIZE) and (address > LINESIZE):
                same = True
                for x in xrange(LINESIZE):
                    if (lastline[x] != input[address+x]):
                        same = False
                        break
            lastline = input[address:address+LINESIZE]
            
            if not (same):
                output += "%.8x  "%address
                if (address + LINESIZE >= inplen):
                    LINESIZE = inplen - address
                for x in xrange(LINESIZE/2):
                    output += "%.2x "%ord(input[address + x])
                output += " "
                for x in xrange(LINESIZE/2, LINESIZE):
                    output += "%.2x "%ord(input[address + x])
                if printText:
                    output += " |"
                    for x in xrange(LINESIZE):
                        inpbyte = input[address+x]
                        ordnum = ord(inpbyte)
                        if (ordnum < 0x20 or ordnum > 0x7e):
                            output += "."
                        else:
                            output += inpbyte
                    output += "|"
                output += "\n"
            address += LINESIZE
        outfile.write(output)
    
    def ihex_load(self, inp, strict=True):
        #return ihexbin(sections, startaddress, chksm_errors, syntax_errors, memory_errors, bytecount_errors, offbyone_errors)
        self.sections = []
        self.startaddress = None
        self.chksm_errors = []
        self.syntax_errors = []
        self.memory_errors = []
        self.bytecount_errors = []
        self.offbyone_errors = []
        self.lines = inp.split()
        
        ### FIXME: handle comments if they exist
        linecount = 0
        secaddress = int(self.lines[0][3:7],16)
        lasttype = -1
        recordtype = -1
        bytes = ""

        for line in xrange(len(self.lines)):
            start = self.lines[line][0]
            bytecount = int(self.lines[line][1:3],16)
            address = int(self.lines[line][3:7],16)
            recordtype = int(self.lines[line][7:9],16)
            data = self.lines[line][9:-2]
            checksum = int(self.lines[line][-2:],16)  #even modified files must have a checksum byte at the end
            if len(data) != (bytecount * 2):  #length of data match what we read for bytecount?
                self.bytecount_errors.append(line)
                print("bytecount_error:  data: %x but should be %x"%(len(data), bytecount*2))
                bytecount = len(data) / 2
            if (len(data) % 2 == 1):     #um... hex bytes require two digits.,..  always...
                self.offbyone_errors.append(line)
                print("offbyone_error (line 0x%x):  expected an even number of bytes, but received %x"%(line, len(data)))
            realchksm = calculate_checksum(self.lines[line][:-2])
            if (checksum != realchksm):
                self.chksm_errors.append(line)
                print("chksm_error (line 0x%x):  expected %x but received %x"%(line, realchksm, checksum))
                
            append = ""
            
            
            #### CREATE A NEW SECTION IF WE CHANGE RECORDTYPES
            #print("Current Type:  %x\t\t Last Type:  %x"%(recordtype,lasttype))
            if (recordtype != lasttype and lasttype != -1):
                #print "Section Type: %x"%recordtype
                self.sections.append((secaddress, lasttype, bytes))
                secaddress = address
                bytes=""
            
            ### INTERPRET DATA AND CONVERT TO ASCII FROM IHEX
            if (address + bytecount > MAX_MEMORY):  # if loading this line would push us past the MAX_MEMORY, error
                self.memory_errors.append(line)
            else:
                if (self.startaddress != None):          # if not the first line (where startaddress doesn't exist)
                    offset = address-self.startaddress
                    if (offset > len(bytes)):
                        if (offset - len(bytes) > bytecount):
                            self.sections.append((secaddress, lasttype, bytes))
                            secaddress = address
                            bytes=""
                        #else:
                            #print "PADDING WITH ZEROS (%x) (%x)"%(offset, len(bytes))
                            #bytes += "\x00"*(address - startaddress - len(bytes))
                    elif (offset < len(bytes)):
                        #print("DEBUG: OVERLAP (%x)"%offset)
                        if (offset + bytecount < len(bytes)):
                            append = bytes[offset+bytecount:]
                        bytes = bytes[:offset]
                else:                               # if it's the first line....
                    self.startaddress = address
                for byte in xrange(0, bytecount):
                    ch = "%c"%(int(data[(byte*2):(byte*2)+2],16))
                    #print "Adding byte: %s"%data[byte*2:byte*2+2]
                    bytes += ch
                bytes += append
            lasttype = recordtype
        self.sections.append((secaddress, lasttype, bytes))

    def getSections(self):
        return self.sections

    def getSectionName(self,sec):
        return secnames[sec[1]]
    
def calculate_checksum(line):
    """ Assume it is the whole line, EXcluding a checksum.
    Returns a python number, not hex-text
    """
    chksum = 0
    if len(line) and line[0] == ':':
        line = line[1:]
    for x in xrange(0,len(line),2):
        #print "adding %s"%line[x:x+2]
        chksum += int(line[x:x+2],16)
    checksum = ((chksum ^ 0xff) +1) & 0xff
    #print "CHECKSUM: %2x"%checksum
    return checksum


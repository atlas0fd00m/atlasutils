#!/usr/bin/env python
import sys

CLOCK = 0           # channel that is used for clock
CLK_TICK = 0        # default, data is read on falling clock edge
NORMAL = (None, 1, 1, 0, 0, 0, 0, 0)  # this is what is logical 0 for each pin.  Clock = pin 0 so it doesn't need one.

filename = sys.argv[1]
if len(sys.argv) > 2:
    CLK_TICK = int(sys.argv[2]) # 0 = use falling clock edge,    1 = use rising clock edge
if len(sys.argv) > 3:
    CLOCK = int(sys.argv[3])    # which channel is used for clock


infile = file(filename).readlines()
description = infile.pop(0)

scope_dataset = [[] for x in range(8)]
scope_metadata = [[] for x in range(8)]
num_dataset = []

for lnum in xrange(len(infile)):
    line = infile[lnum].strip('\n').split(',')
    trigger,stamp,channel,index,type,delay,factor,rate,count = line[:9]
    data = line[9:]
    scope_metadata[lnum%8].append((trigger,stamp,channel,index,type,delay,factor,rate,count))
    scope_dataset[lnum%8].extend(data)

scope_strings = [None for x in range(8)]
for x in range(len(scope_dataset)) :
    scope_strings[x] = "".join(["%c"%y for y in scope_dataset[x]])


for data in scope_dataset:
    for x in xrange(len(data)):
        if data[x] == '0':
            data[x] = 0
        elif data[x] == '5':
            data[x] = 1
    num_dataset.append(data)

def get_bit_data(num_dataset, clk_tick=CLK_TICK, clock_idx=CLOCK):
    global big_data
    """
    interprets each sample stream in reference to the clock line indicated by clock_idx.
    clock_tick indicates which clock level each line is sampled (rising=1, falling=0)
    """
    bit_data = [[] for x in range(8)]
    prevclk = num_dataset[clock_idx][0]
    for idx in xrange(len(num_dataset[clock_idx])):
        clk = num_dataset[clock_idx][idx]
        if clk != prevclk:
            prevclk = clk
            if clk == clk_tick:
                for x in range(8):
                    bit_data[x].append(num_dataset[x][idx])
    return bit_data

jtag_states = [\
        (0x2,0x5,"Exit2-DR", ),        # 0x0
        (0x3,0x5,"Exit-DR", ),         # 0x1
        (0x2,0x1,"Shift-DR", ),        # 0x2
        (0x3,0x0,"Pause-DR", ),        # 0x3
        (0xe,0xf,"Select-IR-Scan", ),  # 0x4
        (0xc,0x7,"Update-DR", ),       # 0x5
        (0x2,0x1,"Capture-DR", ),      # 0x6
        (0x6,0x4,"Select-DR-Scan", ),  # 0x7
        (0xa,0xd,"Exit2-IR", ),        # 0x8
        (0xb,0xd,"Exit-IR", ),         # 0x9
        (0xa,0x9,"Shift-IR", ),        # 0xa
        (0xb,0x8,"Pause-IR", ),        # 0xb
        (0xc,0x7,"RunTest/Idle", ),    # 0xc
        (0xc,0x7,"Update-IR", ),       # 0xd
        (0xa,0x9,"Capture-IR", ),      # 0xe
        (0xc,0xf,"Test/Reset", ),      # 0xf
        ]
debug=True
IRI = []
IRO = []
DRI = []
DRO = []
def interp_jtag(tck=0,tms=1,tdo=2,tdi=3,jtag_state=0xf,clk_tick=CLK_TICK):
    global debug,IRI,IRO,DRI,DRO,num_dataset
    bit_data = get_bit_data(num_dataset, clk_tick, tck)
    data = []
    for x in xrange(len(bit_data[tck])):
        last_state = jtag_state
        jtag_state = jtag_states[jtag_state][bit_data[tms][x]]
        if debug: 
            print >>sys.stderr,(bit_data[tms][x],jtag_state,jtag_states[jtag_state],bit_data[tdo][x])
            data.append("(%s)"%jtag_states[jtag_state][2])

        if last_state == 0x2:     # shift_dr
            DRI.append(bit_data[tdi][x])
            DRO.append(bit_data[tdo][x])
        elif last_state == 0xa:     # shift_ir
            IRI.append(bit_data[tdi][x])
            IRO.append(bit_data[tdo][x])

        if jtag_state == 0x6:       # capture_dr
            DRI = []
            DRO = []
        elif jtag_state == 0x1:     # exit_dr
            pass
        elif jtag_state == 0x5:     # update_dr
            o=0
            for b in DRO:
                o<<=1
                o += b
            i=0
            for b in DRI:
                i<<=1
                i += b
            if debug:
                data.append("%s,%s"%(repr(DRI),repr(DRO)))
            data.append("DRin: %x              DRout: %x"%(i,o))
        elif jtag_state == 0xe:     # capture_ir
            IRI = []
            IRO = []
        elif jtag_state == 0x9:     # exit_ir
            pass
        elif jtag_state == 0xd:     # update_ir
            data.append("IRin: %s     IRout: %s"%(repr(IRI),repr(IRO)))
        elif jtag_state == 0xf:     # Test/Reset
            if last_state != 0xf:
                data.append("==TAP RESET==")
        elif jtag_state == 0xc:     # RunTest/Idle
            data.append("===RUNTEST/IDLE===")
    return data


def interp_biwire(bit_data, clock_idx=CLOCK):
    """
    interprets each sample stream in reference to the clock line indicated by clock_idx.
    instead of sampling on one clock edge or the other, this interprets on both, allowing bidirectional communication on one line
    reference: ChipCon debugging protocol, SPI-BI-Wire and other 2-wire SPI-like protocols
    """
    bytes_rx=[]
    bytes_tx=[]
    try:
        for x in xrange(0,len(bit_data[1][CLK_RX]), 8):
            num = 0
            for y in range(8):
                num <<= 1
                num += bit_data[1][CLK_RX][x+y]
            bytes_rx.append("%c"%num)
    except:
        print sys.exc_info()        

    try:
        for x in xrange(0,len(bit_data[1][CLK_TX]), 8):
            num = 0
            for y in range(8):
                num <<= 1
                num += bit_data[1][CLK_TX][x+y]
            bytes_tx.append("%c"%num)
    except:
        print sys.exc_info()        

    return (bytes_rx, bytes_tx)
#"".join(bytes_rx)
#"".join(bytes_tx)
    
    
def get_bit_strings(bit_data):    
    bit_strings = [[] for x in range(8)]
    for x in range(len(bit_data)) :
        bit_strings[x] = "".join(["%c"%y for y in bit_data[x]])
    return bit_strings



def stats(samplelist):
    results = []
    for x in range(len(stringslist)):
        print "Sample %d"%x
        chars = {}
        for char in stringslist[x]:
            num = chars.setdefault(char,0) + 1
            chars[char] = num
        for char in chars.keys():
            print " %s: %d"%(repr(char), chars[char])
        results.append(chars)
    return results
    


LSB = 1     # least significant bits first
MSB = 0     # most significant bits first
def b2B(bits, normal=0, bitsPerByte=8, SigBit=LSB):
    byte = 0
    try:
        for x in range(bitsPerByte):
            if SigBit == MSB:
                x = bitsPerByte - x
            byte += ((bits[x] ^ normal) << x)
            
        return byte

    except:
        return 0xff

#fixme: this is crap.  doesn't make sense except in one sequence.  if the clock gets off, this is done.
def hexdump(input, LINESIZE=128, outfile = sys.stdout, bitsPerByte=8, startbits=0, stopbits=0, skipsamelines = True, MAX_ONES=9, printText = False):
    """ from this style:
00000020  00 02 80 04 f7 09 d8 fc  78 22 90 10 e3 7a 04 ba  |........x"...z..|
    """
    output = ""
    inplen = len(input)
    address = 0
    lastline = ""
    one_count = 0
    
    while (address < inplen):
        one_count += 1
        same=False
        if skipsamelines and (inplen >= address+LINESIZE) and (address > LINESIZE):
            same = True
            for x in xrange(LINESIZE):
                if (lastline[x] != input[address+x]):
                    same = False
                    break                    
        lastline = input[address:address+LINESIZE]
        keepgoin = True
        if not (same):
            output += "%.8x  "%address
            if (address + LINESIZE >= inplen):
                LINESIZE = inplen - address
            
            for x in xrange(LINESIZE/2):
                bit = input[address + x]
                output += "%x"%(bit)
                if not bit:
                    one_count = 0
                else:
                    one_count += 1
                    if one_count > MAX_ONES:
                        one_count = 0
                        nx = address + x
                        while bit and nx < inplen:
                            bit = input[nx]
                            nx += 1
                            #print ":"+bit+":"
                        output += "\t\t\t %d high-bits\n" % (nx-address-x+MAX_ONES)
                        address = nx
                        keepgoin = False
                        break
            if not keepgoin:
                continue
            output += " "
            for x in xrange(LINESIZE/2, LINESIZE):
                bit = input[address + x]
                output += "%x"%(bit)
                if not bit:
                    one_count = 0
                else:
                    one_count += 1
                    if one_count > MAX_ONES:
                        one_count = 0
                        nx = address + x
                        while bit and nx < inplen:
                            bit = input[nx]
                            nx += 1
                        output += "\t\t\t %d high-bits\n" % (nx-address-x+MAX_ONES)
                        address = nx
                        keepgoin = False
                        break
            if not keepgoin:
                continue
            if printText:
                output += " |"
                for x in xrange(LINESIZE/bitsPerByte):
                    inpbyte = b2B(input[address+x:address+x+bitsPerByte])
                    ordnum = (inpbyte)
                    if (ordnum < 0x20 or ordnum > 0x7e):
                        output += "."
                    else:
                        output += "%c"%inpbyte
                output += "|"
            output += "\n"
        address += LINESIZE
    outfile.write(output)

hexdump (get_bit_data(num_dataset)[1], printText=True)



import sys
import copy


UNIQ_KEYS = [ "CLASS", "UID", "VERSION", "X-KOLAB-CREATIONDATE", "N", "FN" ]

def FNparse(FN):
    comloc = FN.find(",")
    if (comloc > -1):
        FN = FN[comloc+1:].strip() + " " + FN[:comloc].strip()
    return FN

def TELprune(num):
    tel = num.replace('(','')
    tel = tel.replace(')','')
    tel = tel.replace(' ','')
    tel = tel.replace('.','')
    tel = tel.replace('-','')
    tel = tel.replace("'",'')
    tel = tel.replace('"','')
    return tel


class vCard(dict):
    def __init__(self, lines=None):
        if (lines != None):
            self.parse(lines)
    
    def parse(self, lines):
        """  Parses lines of text or an array of lines.  
        Stops at a second "BEGIN:VCARD", at an "END:VCARD", or when runs out of lines
        Returns the number of lines read.
        """
        last = None
        if not (isinstance(lines, list)):
            lines = lines.split('\n')
        
        llen = len(lines)
        #print "LENGTH: %d"%llen
        for idx in range(llen):
            line = lines[idx]
            shortline = line.replace('\t','').replace(' ','').upper()
            #print shortline
            if (shortline == "BEGIN:VCARD" and idx > 0
                    or shortline == "END:VCARD"):
                print "Found a new card... returning..."
                return idx
            
            if (last != None and len (line)>0 and line[0] == " "):
                print "passing:  ==%s=="%line
                pass  # assume the whole thing is read in correctly with the key
            
            elif (shortline.find(":") > -1):  # make sure it's got a key:value pair
                # suck it in!
                values = []
                key,value = line.split(":",1)
                values.append( value.rstrip() )
                key = key.upper()
                last = key
                
                tpi = idx+1
                while (tpi < llen and len(lines[tpi])>0 and lines[tpi][0] == " "):
                    print "appending '%s'"%lines[tpi]
                    values.append(lines[tpi].rstrip()) 
                    tpi +=1
                
                self.push(key,"\n".join(values))
        #sys.stdin.readline()
        return idx
            
            
    def push(self, key, value):
        if (key.upper() in UNIQ_KEYS and self.has_key(key)):
            print >>sys.stderr,"Ignoring (already present): %s:%s"%(key,value)
        else:
            cur = self.get(key,[])
            cur.append(value)
            self[key] = cur
        
    def pop(self, key):
        if self.has_key(key):
            return dict.pop(self, key, 0)
        else:
            raise(Exception("Hey!  No key like that here!  (%s)"%key))
            
    def __repr__(self):
        workself = copy.copy(self)
        
        if workself.has_key("BEGIN"):
            begin = workself.pop("BEGIN")
            output = [ "BEGIN:"+begin[0], ]
        else:
            output = [ "BEGIN:VCARD", ]
        
        if workself.has_key("CLASS"):
            cls = workself.pop("CLASS")
            output.append("CLASS:"+cls[0])

        if workself.has_key("END"):
            endstuff = "END:"+workself.pop("END")[0].strip()+"\n\n"
        #else:
        endstuff = "END:VCARD\n\n"
        
        # Now put the lion-share on there    
        for key,values in workself.iteritems():
            for value in values:
                output.append(key+":"+value)
            
        output.append(endstuff)
        return '\n'.join(output)
        
    def merge(self, ovcard):
        for key,values in ovcard.iteritems():
            for value in values:
                self.push(key,value)


    def compare(self, ovcard):
        same = False
        # Compare "N"
        if self.has_key("N") and ovcard.has_key("N"):
            myln,myfn = self["N"][0].upper().split(";")[:2]
            oln,ofn = ovcard["N"][0].upper().split(";")[:2]
            
            # Don't make them equal just cuz they're both broke
            if len(myln)>0 and len(myfn)>0:
                # Make sure the last and first names match
                if myln == oln and myfn == ofn:
                    same = True
                    print >>sys.stderr,"Match N"
                
        # Compare "FN"
        if self.has_key("FN") and ovcard.has_key("FN"):
            myname = FNparse(self["FN"][0]).upper()
            oname = FNparse(ovcard["FN"][0]).upper()
            
            # Don't make them equal just cuz they're both broke
            if len(myname)>0:
                # Make sure the last and first names match
                if myname == oname:
                    same = True
                    print >>sys.stderr,"Match FN"
                
            
        # Compare "EMAIL"  (NOTE: Not Unique!)
        if self.has_key("EMAIL") and ovcard.has_key("EMAIL"):
            myemails = self["EMAIL"]
            omails  = ovcard["EMAIL"]
            
            for email in myemails:
                for omail in omails:
                    if email == omail:
                        same = True
                        print >>sys.stderr,"Match Email"
        
            
        # Compare "TEL;"s
        # Stary by figuring out all the keys that start in "TEL;"
        mytelkeys = self.getTelKeys()
        otelkeys  = ovcard.getTelKeys()
        
        # Now enumerate all telephone numbers from those key
        mytels = []
        for key in mytelkeys:
            for tel in self[key]:
                mytels.append(TELprune(tel)) # magic
        otels = []
        for key in otelkeys:
            for tel in ovcard[key]:
                otels.append(TELprune(tel))  # magic
        
        # Now, in a very unglorious way, look for matches
        for tel in mytels:
            for otel in otels:
                if tel == otel:
                    same = True
                    print >>sys.stderr,"Match Telephone"
        return same


    def getTelKeys(self):
        retkeys = []
        for key in self.keys():
            if key.startswith("TEL;"):
                retkeys.append(key)
        return retkeys
                

import os


def loadCards(filespec):
    global files,cards,didxs
    if os.stat(filespec).st_nlink == 1:
        cards = [ readCard(filespec) ]   
    else:
        files = os.listdir(filespec)
        cards = []
        for f in files:
            cards.append(readCard(filespec+os.sep+f))
    return cards

def readCard(filepath):
        fin = file(filepath).readlines()
        count = 0
        while (count < len(fin)-1):
            vc = vCard()
            clen = vc.parse(fin[count:])
            count += clen
            cards.append(vc)
        print vc
        return vc
        
def compress(cards):
    didxs = []
    for cidx in range(len(cards)):
        cur = cards[cidx]
        for tcard in cards[:cidx]:
            if (cur.compare(tcard)):
                print >>sys.stderr,"Merging!"
                tcard.merge(cur)
                didxs.insert(0,cidx)
                cards[cidx].DELETE = True
                break
    print >>sys.stderr,"Number of cards before compression: %d"%len(cards)
    print >>sys.stderr,"Number of cards to delete: %d"%len(didxs)
    for didx in didxs:
        try:
            print didx
            if (cards[didx].DELETE):
                cards.pop(didx)
                print >>sys.stderr,"Deleting card index %d"%didx
        except:
            print >>sys.stderr,"DOH!  Not that index! %d"%didx
    print >>sys.stderr,"Number of cards after compression: %d"%len(cards)
    return cards

cards = []
cards2 = []

if __name__ == "__main__":
    sys.argv.pop(0)
    for x in range(len(sys.argv)):
        cards.extend(loadCards(sys.argv[x]))
    
    cards2 = compress(cards)

"""
import vcardtoys
c1 = vcardtoys.vCard(file('SHARED/AddressBook/friend.vcf').read());c1
c2 = vcardtoys.vCard(file('SHARED/AddressBook/friend1.vcf').read());c2
c1.__merge__(c2)
c1

import vcardtoys ; cards = vcardtoys.loadCards('/home/atlas/SHARED/AddressBook/')
cards = compress(cards)

fo = file('output.vcf','w')
for vcard in cards:
    fo.write(repr(vcard)) 

fo.close()

"""

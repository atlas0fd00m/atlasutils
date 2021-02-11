class props (dict):
    ### Saving the asm:
    def save(self, filename = "save.asm"):
        outf = open(filename, "w")
        keys = self.keys()
        keys.sort()
        for i in keys:
            i = i.replace("=", "\\x3d")
            outf.write("%s=%s\n"%(i, mydict.get(i)))
        outf.close()
    
    
    ### Loading the asm:
    def load(self, filename = "save.asm"):
        lines = open(filename).readlines()
        for i in lines:
            addy, asm = i.strip().split("=")
            addy = addy.replace("\x3d", "=")
            self.setdefault(addy, asm)
        return self


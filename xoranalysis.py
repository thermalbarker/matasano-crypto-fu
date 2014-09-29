from cryptobuffer import cryptobuffer
import frequencyanalyser
import string

class xor(object):

    
    def crackhex(self, cypherhex):
        buff = cryptobuffer()
        buff.fromHex(cypherhex)
        results = list()

        # Encrypted with a single character XOR
        for c in string.printable:
            charbuff = buff.singlecharxor(c)
            f = frequencyanalyser.frequency()
            f.addText(charbuff.toString())
            chisq = f.engchisq()
            result = (c, chisq, charbuff)
            results.append(result)
        return sorted(results, key=lambda tup: tup[1])

    def crackfile(self, testfile):
        infile = open(testfile, "r")
        fileresults = list()
        i = 0
        for line in infile:
            i += 1
            cypherhex = line.strip()
            results = self.crackhex(cypherhex)
            for result in results:
                r = (i, result[0], result[1], result[2])
                fileresults.append(r)
        infile.close()
        return sorted(fileresults, key=lambda tup: tup[2])

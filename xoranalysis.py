from cryptobuffer import cryptobuffer
import frequencyanalyser
import string

class xor(object):

    def crackhex(self, cypherhex):
        buff = cryptobuffer()
        buff.fromHex(cypherhex)
        cyphertext = buff.toString()
        length = len(cyphertext)
        print "Encrypted text: ", buff.toString()
        results = {}

        # Encrypted with a single character XOR
        for c in string.uppercase:
            charbuff = cryptobuffer()
            charbuff.fromString(c * length)
            print "Decrypting with: " , charbuff.toString()
            charbuff.xor(buff)
            print charbuff.toString()
            f = frequencyanalyser.frequency()
            f.addText(charbuff.toString())
            chisq = f.engchisq()
            results[c] = chisq
            print "Chi2 = ", chisq
        minkey = min(results, key=results.get)
        print "Most likely character: ", minkey
        return results

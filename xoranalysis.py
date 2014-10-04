from cryptobuffer import cryptobuffer
import frequencyanalyser
import string

class xor(object):

    
    def crackhex(self, cypherhex):
        buff = cryptobuffer()
        buff.fromHex(cypherhex)
        return self.crack_singlechar_xor(buff)
        
    def crack_singlechar_xor(self, buff):
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

    def find_keysize(self, buff, maxkeysize):
        results = list()
        for i in range(1, maxkeysize + 1):
            # with keysize i, we can do buff.size / 2*i distances
            hams = len(buff.mBytes) // (2*i) # // means floor division
            totalham = 0.0
            k = 0
            for j in range(1, hams + 1):
                slice1 = buff.subBuffer(k, i)
                k += i
                slice2 = buff.subBuffer(k, i)
                k += i
                distance = slice1.hamming(slice2)
                totalham += distance
            # Average distance
            totalham = totalham / hams
            # Normalise by the keysize
            totalham = totalham / i
            # add to results
            row = (i, totalham)
            results.append(row)
        return sorted(results, key=lambda tup: tup[1])

    def reslice_blocks(self, buff, slicesize):
        result = list()
        slices = len(buff.mBytes) // slicesize
        for i in range(0, slicesize):
            thisslice = cryptobuffer()
            k = i
            for j in range(0, slices):
                thisslice.mBytes.append(buff.mBytes[k])
                k+=slicesize
            result.append(thisslice)
        return result
                                        
    def crack_xor(self, buff, consider_keys = 1, max_keysize = 40):
        results = list()
        keylengths = self.find_keysize(buff, max_keysize)
        for key_tries in range(0, consider_keys):
            this_keylength = keylengths[key_tries][0]
            print "Attempting key length: ", this_keylength
            sliced_buffs = self.reslice_blocks(buff, this_keylength)
            key = cryptobuffer()
            for buff_slice in sliced_buffs:
                slice_results = self.crack_singlechar_xor(buff_slice)
                key.mBytes.append(slice_results[0][0])
            print "Key[", key_tries, "] = ", key.toString()
            results.append(key)
        return results

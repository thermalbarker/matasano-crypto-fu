from cryptobuffer import cryptobuffer
import frequencyanalyser
import string

class xor(object):

    def __init__(self, ref_freq = None):
        if ref_freq is None:
            self.ref_freq = frequencyanalyser.englishfrequency()
        else:
            self.ref_freq = ref_freq

    def crackhex(self, cypherhex):
        buff = cryptobuffer()
        buff.fromHex(cypherhex)
        return self.crack_singlechar_xor(buff)
        
    def crack_singlechar_xor(self, buff):
        results = list()
        # Encrypted with a single character XOR
        # does not have to be just the printable letters
        for i in range(0, 255):
            c = chr(i)
            charbuff = buff.singlecharxor(c)
            f = frequencyanalyser.frequency()
            f.addText(charbuff.toString())
            chisq = f.compare(self.ref_freq)
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

    # Takes blocks of keysize in pairs and compares each pair
    def calculateHam(self, buff, keysize):
        # with keysize i, we can do buff.size / 2*i distances
        hams = len(buff.mBytes) // (2*keysize) # // means floor division
        totalham = 0.0
        k = 0
        for j in range(1, hams + 1):
            slice1 = buff.subBuffer(k, keysize)
            k += keysize
            slice2 = buff.subBuffer(k, keysize)
            k += keysize
            distance = slice1.hamming(slice2)
            totalham += distance
        # Average distance
        totalham = totalham / hams
        # Normalise by the keysize
        totalham = totalham / keysize
        # add to results
        return totalham

    # Loops over all block combinations
    def miniHam(self, buff, keysize):
        # with keysize i, we can do buff.size / 2*i distances
        hams = len(buff.mBytes) // keysize # // means floor division
        n = 0.0
        totalham = 0.0
        minimum = 1000.0
        for j in range(0, hams):
            k = j * keysize
            slice1 = buff.subBuffer(k, keysize)
            for l in range (j + 1, hams):
                k2 = l * keysize
                slice2 = buff.subBuffer(k2, keysize)
                distance = float(slice1.hamming(slice2)) / float(keysize)
                #print "s[",j,"]: ", slice1.toHex(), " vs s[", l, "] ", slice2.toHex(), " d: ", distance
                # Total
                totalham += distance
                n += 1
                # Minimum
                minimum = min(minimum, distance)
        # Average distance
        if (n != 0):
            totalham = totalham / n
        else:
            totalham = 99999.9
        # add to results
        return (totalham, minimum)


    def find_keysize(self, buff, maxkeysize):
        results = list()
        for i in range(1, maxkeysize + 1):
            row = (i, self.calculateHam(buff, i))
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
                #print "Slice:"
                #if buff_slice is sliced_buffs[0]:
                #    for r in slice_results:
                #        print  r[0], '{:06}'.format(r[1]), r[2].toPrintable()
                key.mBytes.append(slice_results[0][0])
            print "Key[", key_tries, "] = ", key.toBase64()
            results.append(key)
        return results

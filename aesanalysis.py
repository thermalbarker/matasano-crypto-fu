import sys
from aes import aes, AesBlockmode
from xoranalysis import xor
from cryptobuffer import cryptobuffer
from frequencyanalyser import englishfrequency, filefrequency

class aesanalysis(object):

    padbyte = 0xAA

    def __init__(self):
        self.freq = englishfrequency()
        #self.freq = filefrequency("data/vanilla.txt")
        self.xor = xor(self.freq)
        self.aes = aes()
    
    def detectAesEcb(self, testfile):
        infile = open(testfile, "r")
        fileresults = list()
        i = 0
        for line in infile:
            i += 1
            cypherhex = cryptobuffer()
            cypherhex.fromHex(line)
            ham = self.xor.miniHam(cypherhex, aes.blockSize)
            row = (i, ham[0], ham[1], cypherhex)
            fileresults.append(row)
        infile.close()
        return sorted(fileresults, key=lambda tup: tup[1])

    def detectAesEcbFunc(self, func):
        plaintext = cryptobuffer()
        cypher = cryptobuffer()
        # Plain text is repeated string
        # must be long enough to allow for 10-20 bytes of padding
        txt = "YELLOW SUBMARINE" * 4
        plaintext.fromString(txt)
        # Perform encryption
        cypher.mBytes = func(plaintext.mBytes)
        ham = self.xor.miniHam(cypher, aes.blockSize)    
        return (ham[1] == 0.0)

    def findKeyLength(self, func, maxLen):
        results = list()
        mystring = cryptobuffer()
        for i in range(1, maxLen + 1):
            mystring.mBytes.append(self.padbyte)
            mystring.mBytes.append(self.padbyte)
            cypher = cryptobuffer()
            cypher.mBytes = func(mystring.mBytes)
            # Just take the first i * 2 bytes
            cypher.mBytes = cypher.mBytes[0:i*2]
            ham = self.xor.miniHam(cypher, i)
            row = (i, ham[1])
            results.append(row)
        return sorted(results, key=lambda tup: tup[1])


    def makeEcbDict(self, func, decrypted, blocksize):
        result = list()
        mystring = cryptobuffer()
        cypher = cryptobuffer()
        blockoffset = len(decrypted) % blocksize
        blocknumber = len(decrypted) // blocksize
        start = blocknumber*blocksize
        end = (blocknumber+1)*blocksize
        # Initialised my string with padding
        for i in range(0, blocksize - blockoffset - 1):
            mystring.mBytes.append(self.padbyte)
        # Add what has already been decrypted
        mystring.mBytes.extend(decrypted.mBytes)
        # Add a dummy byte
        mystring.mBytes.append(self.padbyte)
        #print blockoffset, blocknumber, blocksize, len(mystring.mBytes)
        # Build the dictionary
        for i in range(0, 256):
            mystring.mBytes[-1] = i
            cypher.mBytes = func(mystring.mBytes)[start:end]
            #print i, len(mystring.mBytes), "[", start, ":", end, "]", cypher.toHex()
            result.append(cypher.mBytes)
        return result

    def findEcbByte(self, func, blocksize):
        cypher = cryptobuffer()
        decrypted = cryptobuffer()
        # Get the total length of the unencrypted string
        totallen = len(func(bytearray()))
        print "Total number of bytes: ", totallen
        # Initialised my string
        for j in range(0, totallen):
            # Build an array of padding bytes:
            # 'AAAAAAAAAAAAAAA'
            # which is 15 bytes long
            mystring = cryptobuffer()
            blockoffset = len(decrypted) % blocksize
            blocknumber = len(decrypted) // blocksize
            start = blocknumber*blocksize
            end = (blocknumber+1)*blocksize
            for i in range(1, blocksize-blockoffset):
                mystring.mBytes.append(self.padbyte)
            # Encrypt with the string appended before the unknown text
            # the 16th byte will be the 1st byte of the text
            cypher.mBytes = func(mystring.mBytes)[start:end]
            # Add the existing decrypted message
            mystring.extend(decrypted.mBytes)
            # Build a dictionary of possible encrypted messages
            myList = self.makeEcbDict(func, decrypted.mBytes, blocksize) 
            # Find the byte of the unknown text
            try:
                byte = myList.index(cypher.mBytes)
            except ValueError:
                print "Could not find encrypted block ==> finished"
                break

            decrypted.mBytes.append(byte)
            print "Decrypted ", j, " bytes:"
            print "------------------------"
            print decrypted.toString()
            print "------------------------"
        return decrypted

    def decryptAesEcbFunc(self, func):
        # Find key length
        keysizes = self.findKeyLength(func, 40)
        keysize = keysizes[0][0]
        print "Keysize: ", keysize
        # Detect ECB
        usingEcb = self.detectAesEcbFunc(func)
        if (usingEcb):
            print "Using ECB!"
        result =  self.findEcbByte(func, keysize)
        # For some reason, always an additional byte, so delete it:
        del(result[-1])
        return result

    # Provides solution for challenge 20
    def decryptCtrFixedNonce(self, cypherTexts):
        plainTexts = []
        truncatedTexts = []
        cat = cryptobuffer()
        P2 = cryptobuffer()

        print "Breaking Fixed-Nonce CTR"

        # Find smallest line length
        mini = sys.maxint
        for cypherText in cypherTexts:
            mini = int(min(mini, len(cypherText)))
        print "Minimum cyphertext length: ", mini
        # Truncate to smallest length and pack
        for cypherText in cypherTexts:
            truncated = cypherText[0:mini]
            truncatedTexts.append(truncated)
            cat.mBytes.extend(truncated)
            
        # Use xor analysis to crack
        P2s = self.xor.crack_xor(cat, 1, mini)
        for t in truncatedTexts:
            tBuff = cryptobuffer()
            tBuff.mBytes = t
            plain = tBuff.xor(P2s[0])
            print plain.toPrintable()
            plainTexts.append(plain)
    
        return plainTexts


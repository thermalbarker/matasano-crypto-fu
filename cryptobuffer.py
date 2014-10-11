import base64
import binascii
import math

class cryptobuffer(bytearray):

    def __init__(self):
        self.mBytes = self
    
    def fromHex(self, text):
        text = text.strip()
        text.replace(" ", "")
        self.mBytes = bytearray.fromhex(text)

    def toHex(self):
        return binascii.hexlify(self.mBytes)
    
    def toBase64(self):
        return base64.b64encode(self.toString())

    def fromBase64(self, text):
        text.strip()
        text.replace(" ", "")
        self.mBytes = bytearray(base64.b64decode(text))

    def fromString(self, text):
        self.fromBase64(text.encode('base64','strict'))

    def toString(self):
        return str(self.mBytes)

    def fromBase64File(self, filename):
        infile = open(filename, "r")
        self.mBytes = bytearray()
        for line in infile:
            bufferline = cryptobuffer()
            bufferline.fromBase64(line.strip())
            self.mBytes.extend(bufferline.mBytes)
        infile.close()

    def singlecharxor(self, char):
        charbuff = cryptobuffer()
        length = len(self.toString()) 
        charbuff.fromString(char * length)
        return self.xor(charbuff)

    def xor(self, other):
        result = cryptobuffer()
        b = bytearray(len(self.mBytes))
        if (len(other.mBytes) > 0):
            j = 0
            for i in range(len(self.mBytes)):
                # Reset j for a repeating key xor
                if (j >= len(other.mBytes)):
                    j = 0
                b[i] = self.mBytes[i] ^ other.mBytes[j]
                j += 1
            result.mBytes = b
        return result

    def bitCount(self):
        bitsOne = 0
        for byte in self.mBytes:
            bitsOne += bin(byte).count("1")
        return bitsOne

    def hamming(self, other):
        return self.xor(other).bitCount()
        
    def subBuffer(self, start, length):
        result = cryptobuffer()
        result.mBytes = self.mBytes[start:start+length]
        return result

    def padPks7(self, padlength):
        if (padlength < len(self.mBytes)):
            raise Exception("Padding length must be larger than buffer")
        padbyte = padlength - len(self.mBytes)
        for i in range(len(self.mBytes), padlength):
            self.mBytes.append(padbyte)

    def padPks7Block(self, blocksize):
        result = cryptobuffer()
        blocks = int(math.ceil(float(len(self.mBytes)) / float(blocksize)))
        self.padPks7(blocks * blocksize)

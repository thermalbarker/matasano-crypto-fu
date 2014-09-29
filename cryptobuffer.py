import base64
import binascii

class cryptobuffer(object):

    def __init__(self):
        self.mBytes = bytearray()
    
    def fromHex(self, text):
        self.mBytes = bytearray.fromhex(text)

    def toHex(self):
        return binascii.hexlify(self.mBytes)
    
    def toBase64(self):
        return base64.b64encode(self.toString())

    def fromBase64(self, text):
        self.mBytes = bytearray(base64.b64decode(text))

    def fromString(self, text):
        self.fromBase64(text.encode('base64','strict'))

    def toString(self):
        return str(self.mBytes)

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



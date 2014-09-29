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

    def xor(self, other):
        b = bytearray(len(self.mBytes))
        for i in range(len(self.mBytes)):
            b[i] = self.mBytes[i] ^ other.mBytes[i]
        self.mBytes = b
            



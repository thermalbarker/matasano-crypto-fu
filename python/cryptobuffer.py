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
        self.mBytes = str.encode(text)

    def toString(self):
        return str(self.mBytes)

    def xor(self, other):
        self.mBytes = self.mBytes ^ other.mBytes



from aes import aes
from aes import AesBlockmode
from cryptobuffer import cryptobuffer
import random

class blackbox(object):

    def __init__(self):
        self.mAes = aes()
        random.seed()
        self.algo = random.choice(list(AesBlockmode))
        self.key = self.randomBytes(aes.blockSize)
        self.aesEcbUnknown = bytearray()
        self.nonce = "\x00" * 8

    def randomBytes(self, length):
        key = bytearray(length)
        for i in range(0, length):
            key[i] = random.randrange(aes.blockSize)
        return key

    def encryptAesOrEcb(self, buff):
        result = bytearray()
        #key = self.randomBytes(aes.blockSize)
        if (self.algo == AesBlockmode.ECB):
            result = self.mAes.encryptECB(buff, self.key)
        else:
            iv = self.randomBytes(aes.blockSize)
            result = self.mAes.encryptCBC(buff, self.key, iv)
        return result

    def encryptCtr(self, buff):
        return self.mAes.encryptCTR(buff, self.key, self.nonce)

    def addRandomBytes(self, buff):
        result = self.randomBytes(random.randint(5,10))
        result.extend(buff)
        result.extend(self.randomBytes(random.randint(5,10)))
        return result

    def blackBoxFunction(self, buff):
        padded = self.addRandomBytes(buff)
        result = self.encryptAesOrEcb(padded)
        return result

    def blackBoxFunction2(self, buff):
        plaintext = cryptobuffer()
        plaintext.mBytes.extend(buff)
        plaintext.mBytes.extend(self.aesEcbUnknown)
        plaintext.padPks7Block(aes.blockSize)
        return self.mAes.encryptECB(plaintext, self.key)

    def encryptCtrLinesFromFile(self, filename):
        encrypted = []
        plain = []
        infile = open(filename, "r")
        for line in infile:
            bufferline = cryptobuffer()
            bufferline.fromBase64(line.strip())
            cyphertext = self.encryptCtr(bufferline.mBytes)
            encrypted.append(cyphertext)
            plain.append(bufferline.mBytes)
        infile.close()
        return (plain, encrypted)

    def encryptWithCtr(self, plain):
        return self.encryptCtr(plain)

    # The read write function
    def editCtr(self, cypherText, offset, newtext):
        return self.mAes.reencryptCTR(cypherText, self.key, self.nonce, offset, newtext)

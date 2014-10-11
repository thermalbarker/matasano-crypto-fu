from aes import aes
from aes import AesBlockmode
import random

class blackbox(object):

    def __init__(self):
        self.mAes = aes()
        random.seed()
        self.algo = random.choice(list(AesBlockmode))
        self.ecbKey = self.randomBytes(aes.blockSize)
        self.aesEcbUnknown = bytearray()

    def randomBytes(self, length):
        key = bytearray(length)
        for i in range(0, length):
            key[i] = random.randrange(aes.blockSize)
        return key

    def encryptAesOrEcb(self, buff):
        result = bytearray()
        key = self.randomBytes(aes.blockSize)
        if (self.algo == AesBlockmode.ECB):
            result = self.mAes.encryptECB(buff, key)
        else:
            iv = self.randomBytes(aes.blockSize)
            result = self.mAes.encryptCBC(buff, key, iv)
        return result

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
        plaintext = bytearray()
        plaintext.extend(buff)
        plaintext.extend(self.aesEcbUnknown)
        return self.mAes.encryptECB(plaintext, self.ecbKey)

from collections import OrderedDict
from aes import aes
from cryptobuffer import cryptobuffer
import random

class webprofiler(object):

    def __init__(self):
        self.uid = 10
        self.mAes = aes()
        random.seed()
        self.ecbKey = self.randomBytes(aes.blockSize)

    def randomBytes(self, length):
        key = bytearray(length)
        for i in range(0, length):
            key[i] = random.randrange(aes.blockSize)
        return key

    def parseWebString(self, string):
        result = OrderedDict()
        # e.g. foo=bar&baz=qux&zap=zazzle
        for keyvalue in string.split('&'):
            key = keyvalue.split('=')[0]
            value = keyvalue.split('=')[1]
            result[key] = value
        return result

    def makeWebString(self, dic):
        result = ""
        first = True
        for key in dic:
            if not first:
                result += "&"
            first = False
           # eat = and &
            keyforstring = key.translate(None, '=&')
            valueforstring = dic[key].translate(None, '=&')
            result += keyforstring + "=" + valueforstring
        return result

    def profile_for_clear(self, email):
        d = OrderedDict()
        d['email'] = str(email)
        d['uid'] = str(self.uid)
        d['role'] = 'user'
        return self.makeWebString(d)

    def profile_for(self, email):
        encrypted = cryptobuffer()
        clear = self.profile_for_clear(email)
        encrypted.fromString(clear)
        encrypted.padPks7Block(aes.blockSize)
        return self.mAes.encryptECB(encrypted.mBytes, self.ecbKey)

    def extract_profile(self, cyphertext):
        clear = cryptobuffer()
        clear.mBytes = self.mAes.decryptECB(cyphertext, self.ecbKey)
        clear.stripPks7Padding()
        return self.parseWebString(clear.toString())

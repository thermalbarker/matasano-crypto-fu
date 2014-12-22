from collections import OrderedDict
from aes import aes
from cryptobuffer import cryptobuffer
import random

class webprofiler(object):


    def __init__(self):
        self.uid = 10
        self.mAes = aes()
        random.seed()
        self.aesKey = self.randomBytes(aes.blockSize)
        self.iv = cryptobuffer()
        self.iv.fromHex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")

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
            # eat = and & to stop basic hacks
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
        return self.mAes.encryptECB(encrypted.mBytes, self.aesKey)

    def extract_profile(self, cyphertext):
        clear = cryptobuffer()
        clear.mBytes = self.mAes.decryptECB(cyphertext, self.aesKey)
        clear.stripPks7Padding()
        return self.parseWebString(clear.toString())

    def cooking_user_bacon(self, userstring):
        encrypted = cryptobuffer()
        d = OrderedDict()
        d['comment1'] = "cooking MCs"
        d['userdata'] = userstring
        d['comment2'] = "like a pound of bacon"
        encrypted.fromString(self.makeWebString(d))
        encrypted.padPks7Block(aes.blockSize)
        return self.mAes.encryptCBC(encrypted.mBytes, self.aesKey, self.iv.mBytes)

    def search_for_admin(self, cyphertext):
        admin = False
        clear = cryptobuffer()
        clear.mBytes = self.mAes.decryptCBC(cyphertext, self.aesKey, self.iv.mBytes)
        try:
            if not clear.stripPks7Padding():
                throw
            d = self.parseWebString(clear.toString())
            if (d['admin'] == 'true'):
                admin = True
        except:
            admin = False
        return admin

    def random_secret(self, secrets_file):
        secret = cryptobuffer()
        secret.fromRandomLineInBase64File(secrets_file)
        secret.padPks7Block(aes.blockSize)
        secret.mBytes = self.mAes.encryptCBC(secret.mBytes, self.aesKey, self.iv.mBytes)
        return self.iv.mBytes, secret.mBytes

    def cbc_padding_oracle(self, cyphertext):
        clear = cryptobuffer()
        clear.mBytes = self.mAes.decryptCBC(cyphertext, self. aesKey, self.iv.mBytes)
#        print clear.toHexBlocks(aes.blockSize)
        return clear.isPks7Padded()

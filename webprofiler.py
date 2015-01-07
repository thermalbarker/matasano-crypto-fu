from collections import OrderedDict
from aes import aes
from cryptobuffer import cryptobuffer
import random, sys

class webprofiler(object):


    def __init__(self):
        self.uid = 10
        self.mAes = aes()
        random.seed()
        self.aesKey = self.randomBytes(aes.blockSize)
        self.iv = bytearray(self.mAes.blockSize)
        self.nonce = bytearray(8)
        self.encrypt = self.encryptCBC
        self.decrypt = self.decryptCBC

    def randomBytes(self, length):
        key = bytearray(length)
        for i in range(0, length):
            key[i] = random.randrange(256)
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

    # Sets of functions to set the encryption type

    # CBC
    def setCBC(self):
        self.encrypt = self.encryptCBC
        self.decrypt = self.decryptCBC

    def encryptCBC(self, plain):
        plain.padPks7Block(aes.blockSize)
        return self.mAes.encryptCBC(plain.mBytes, self.aesKey, self.iv)

    def decryptCBC(self, cypher):
        plain = cryptobuffer()
        plain.mBytes = self.mAes.decryptCBC(cypher, self.aesKey, self.iv)
        if not plain.stripPks7Padding():
            raise ValueError("Invalid Padding")
        return plain
    
    # CTR
    def setCTR(self):
        self.encrypt = self.encryptCTR
        self.decrypt = self.decryptCTR

    def encryptCTR(self, plain):
        return self.mAes.encryptCTR(plain.mBytes, self.aesKey, self.nonce)

    def decryptCTR(self, cypher):
        plain = cryptobuffer()
        plain.mBytes = self.mAes.decryptCTR(cypher, self.aesKey, self.nonce)
        return plain

    # CBC with key as iv
    def setCBC_IVkey(self):
        self.encrypt = self.encryptCBC_IVkey
        self.decrypt = self.decryptCBC_IVkey

    def encryptCBC_IVkey(self, plain):
        plain.padPks7Block(aes.blockSize)
        return self.mAes.encryptCBC(plain.mBytes, self.aesKey, self.aesKey)

    def decryptCBC_IVkey(self, cypher):
        plain = cryptobuffer()
        plain.mBytes = self.mAes.decryptCBC(cypher, self.aesKey, self.aesKey)
        # Strip padding if it is there, ignore errors
        plain.stripPks7Padding()
        # Check for ascii characters
        if not plain.hasOnlyPrintable():
            # If there are non-valid ascii characters, return the plaintext!
            raise ValueError(plain.toBase64())
        return plain

    # The admin functions
    def cooking_user_bacon(self, userstring):
        plain = cryptobuffer()
        d = OrderedDict()
        d['comment1'] = "cooking MCs"
        d['userdata'] = userstring
        d['comment2'] = "like a pound of bacon"
        plain.fromString(self.makeWebString(d))
        return self.encrypt(plain)

    def search_for_admin(self, cyphertext):
        admin = False
        plain = self.decrypt(cyphertext)
        d = self.parseWebString(plain.toString())
        if 'admin' in d and (d['admin'] == 'true'):
            admin = True
        else:
            admin = False
        return admin
  
    def random_secret(self, plain):
        secret = cryptobuffer()
        secret.fromString(plain)
        secret.mBytes = self.encryptCBC(secret)
        return self.iv, secret.mBytes

    def cbc_padding_oracle(self, cyphertext):
        clear = cryptobuffer()
        clear.mBytes = self.mAes.decryptCBC(cyphertext, self.aesKey, self.iv)
#        print clear.toHexBlocks(aes.blockSize)
        return clear.isPks7Padded()

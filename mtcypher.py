import random
import string
import time
from twister import twister
from cryptobuffer import cryptobuffer

class mtcypher():

    def __init__(self, key = None, preamble_len = None):
        random.seed()
        self.mt = twister()
        self.key = cryptobuffer()
        if not key:
            self.seed_now()
        else:
            self.key.mBytes = key
        if not preamble_len:
            preamble_len = random.randrange(5, 20)
        self.preamble = self.gen_preamble(preamble_len)

    def seed_int(self, seed):
        # Keep to 16 bits
        self.key.fromInt(seed & 0xFFFF)
        print "MT key set to:", self.key.toHex()

    def seed_now(self):
        self.seed_int(int(time.time()))

    def encrypt(self, plain):
        cypher = bytearray()
        # Seed MT with 16-bit key
        self.mt.set_seed(self.key.toInt())
        for b in plain:
            # Generate one byte
            k = self.mt.rand() & 0xFF
            cypher.append( b ^ k )
        return cypher

    def decrypt(self, cypher):
        return self.encrypt(cypher)

    def gen_preamble(self, size=6, chars=string.printable):
        return ''.join(random.choice(chars) for _ in range(size))

    def password_token(self, password):
        token = cryptobuffer()
        token.fromString(self.preamble + password)
        return self.encrypt(token.mBytes)

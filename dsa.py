import cryptomath
import hashlib
from random import randrange
from cryptobuffer import cryptobuffer

class dsa(object):

    def __init__(self, p = None, q = None, g = None):
        # Parameter generation not done here.
        # These parameters are from http://cryptopals.com/sets/6/challenges/43 
        if (p is None) or (q is None):
            self.p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
            self.q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
        else:
            self.p = p
            self.q = q

        if (g is None):
            self.g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
        else:
            self.g = g

    def hash(self, m):
        h = hashlib.sha1()
        r = cryptobuffer()
        b = cryptobuffer()
        b.fromString(m)
        h.update(b.mBytes)
        r.mBytes = h.digest()
        return r.toInt()

    def get_pub_key(self, x):
        return cryptomath.modexp(self.g, x, self.p)

    def gen_key_pair(self):
        x = randrange(0, self.q)
        y = self.get_pub_key(x)
        return x, y

    def sign(self, x, m):
        k = randrange(0, self.q)
        r = cryptomath.modexp(self.g, k, self.p) % self.q
        s = ((self.hash(m) + x * r) * cryptomath.modinv(k, self.q)) % self.q
        return r, s
        
    def verify(self, y, m, r, s):
        w = cryptomath.modinv(s, self.q)
        u1 = (self.hash(m) * w) % self.q
        u2 = (r * w) % self.q
        u1 = cryptomath.modexp(self.g, u1, self.p)
        u2 = cryptomath.modexp(y, u2, self.p)
        v = u1 * u2 % self.p % self.q
        return v == r

    def recover_x(self, k, m, r, s):
        a = ((s * k) - self.hash(m)) % self.q
        b = cryptomath.modinv(r, self.q)
        x = (a * b) % self.q
        return x

    # Here m1 and m2 are the messages themselves (not the hash as in the challenges)
    def recover_k(self, m1, m2, s1, s2):
        h1 = self.hash(m1)
        h2 = self.hash(m2)
        s_diff = (s1 - s2) % self.q
        s_inv = cryptomath.modinv(s_diff, self.q)
        h_diff = (h1 - h2) % self.q
        k = (h_diff * s_inv) % self.q
        return k

    # If using manipulated params (g = p + 1) this generates a valid signature for any message
    def magic_signature(self, y):
        z = randrange(0, self.q)
        r = cryptomath.modexp(y, z, self.q)
        s = (cryptomath.modinv(z, self.q) * r) % self.q
        return r, s


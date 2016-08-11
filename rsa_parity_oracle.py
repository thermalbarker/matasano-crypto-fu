import rsa
from cryptobuffer import cryptobuffer

class oracle(object):
    e = 3

    def __init__(self):
        self.d, self.n = rsa.gen_key_pair(self.e)

    def encrypt(self, m):
        return rsa.encrypt(m, self.e, self.n)

    def get_pub_key(self):
        return self.n

    def parity(self, c):
        # Decrypt
        m = rsa.decrypt(c, self.d, self.n)
        return (m % 2) == 0

class cracker(object):

    def __init__(self, o):
        # Parity function
        self.o = o

    def decrypt(self, c):
        # Get the public key
        n = self.o.get_pub_key()
        print "public key: ", n
        # To double a plaintext, multiply the cyphertext by 2 encrypted
        k = self.o.encrypt(2)
        # for printing
        bu = cryptobuffer()

        lower = 0
        upper = n
        factor = 1
        c2 = c

        for i in range(n.bit_length()):
            c2 = (c2 * k) % n
            p = self.o.parity(c2)
            diff = upper - lower
            upper *= 2
            lower *= 2
            factor *= 2
            if p:
                upper -= diff
            else:
                lower += diff

            bu.fromInt(upper // factor)
            print bu.toPrintable()

        return bu.toInt()

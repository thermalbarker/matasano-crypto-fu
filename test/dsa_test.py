import unittest
import random
import itertools
from dsa import dsa
import cryptomath
from cryptobuffer import cryptobuffer

class dsa_test(unittest.TestCase):

    m = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"
    # Public key and signature from challenge 43
    y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940

    # Public key from challenge 44
    y44 = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821

    def setUp(self):
        random.seed()

    def test_hash_zero(self):
        d = dsa()
        h = d.hash("")
        self.assertEqual(0xda39a3ee5e6b4b0d3255bfef95601890afd80709, h)

    def test_hash(self):
        d = dsa()
        h = d.hash(self.m)
        self.assertEqual(0xd2d0714f014a9784047eaeccf956520045c45265, h)

    def test_verify(self):
        d = dsa()
        self.assertTrue(d.verify(self.y, self.m, self.r, self.s))

    def test_sign_verify(self):
        d = dsa()
        x, y = d.gen_key_pair()
        r, s = d.sign(x, self.m)
        self.assertTrue(d.verify(y, self.m, r, s))
        
    def private_key_hash(self, x):
        d = dsa()
        # Now check the hash of the private key
        x_buf = cryptobuffer()
        x_buf.fromInt(x)
        return d.hash(x_buf.toHex())        

    def test_key_recovery(self):
        d = dsa()
        
        success = False

        # Cheating here to reduce run-time (range should start from 0)
        for k in range(16384, 2 ** 16):
            x = d.recover_x(k, self.m, self.r, self.s)
            y = d.get_pub_key(x)
            if y == self.y:
                print "x: ", x
                print "k: ", k
                success = True
                break

        self.assertTrue(success)
        x_hash = self.private_key_hash(x)
        self.assertEqual(0x0954edd5e0afe5542a4adf012611a91912a3ec16, x_hash)

    def load_signatures(self, filename):
        signatures = []
        lines = [line.split(": ")[1].rstrip('\n') for line in open(filename)]
        n = len(lines) / 4
        for i in range(0, n):
            msg = lines[i * 4]
            s = int(lines[i * 4 + 1])
            r = int(lines[i * 4 + 2])
            m = int(lines[i * 4 + 3], 16)
            signatures.append( (msg, s, r, m) )
        return signatures

    def test_repeated_nonce(self):
        d = dsa()
        success = False
        sigs = self.load_signatures("data/44.txt")
        # Try each pair of lines
        for pair in itertools.permutations(sigs, 2):
            m1 = pair[0][0]
            m2 = pair[1][0]
            s1 = pair[0][1]
            s2 = pair[1][1]
            r1 = pair[0][2]
            r2 = pair[1][2]
            k = d.recover_k(m1, m2, s1, s2)
            x = d.recover_x(k, m1, r1, s1)
            y = d.get_pub_key(x)
            if y == self.y44:
                success = True
                break

        self.assertTrue(success)
        x_hash = self.private_key_hash(x)
        self.assertEqual(0xca8f6f7c66fa362d40760d135b763eb8527d3d52, x_hash)

    def test_param_manipulation_g_zero(self):
        d = dsa(g = 0)
        x, y = d.gen_key_pair()
        r, s = d.sign(x, self.m)
        # r is always zero!
        print "r: ", r
        print "s: ", s
        # Verify signature
        self.assertTrue(d.verify(y, self.m, r, s))
        # We can 'sign' anything with r = 0 and arbitrary s
        self.assertTrue(d.verify(y, self.m, 0, 1234))

    def test_param_manipulation_g_pplusone(self):
        # Manipulated parameters
        p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
        q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
        g = p + 1

        d = dsa(p, q, g)
        x, y = d.gen_key_pair()
        r, s = d.magic_signature(y)
        self.assertTrue(d.verify(y, self.m, r, s))
        self.assertTrue(d.verify(y, "Hello, world", r, s))
        self.assertTrue(d.verify(y, "Goodbye, world", r, s))


if __name__ == '__main__':
    unittest.main()

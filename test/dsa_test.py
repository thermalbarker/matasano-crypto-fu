import unittest
import random
from dsa import dsa
import cryptomath

class dsa_test(unittest.TestCase):

    m = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"
    # Public key and signature from challenge 43
    y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940

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
        
if __name__ == '__main__':
    unittest.main()

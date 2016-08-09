import unittest
import random
from dsa import dsa
import cryptomath

class dsa_test(unittest.TestCase):

    m = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"

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

    def test_sign_verify(self):
        d = dsa()
        x, y = d.gen_key_pair()
        r, s = d.sign(x, self.m)
        self.assertTrue(d.verify(y, self.m, r, s))
        
if __name__ == '__main__':
    unittest.main()

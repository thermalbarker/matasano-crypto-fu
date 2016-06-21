import unittest
import random
from diffiehellman import tom_modexp

class diffiehellman_test(unittest.TestCase):

    def test_mymodexp(self):
        A = tom_modexp(4, 13, 497)
        self.assertEqual(445, A)

    def check_shared(self, p, g):
        a = random.randrange(0, 10000) % p
        A = tom_modexp(g, a, p)

        b = random.randrange(0, 10000) % p
        B = tom_modexp(g, b, p)

        s_a = tom_modexp(B, a, p)
        s_b = tom_modexp(A, b, p)

        self.assertEqual(s_a, s_b)

    def test_shared_secret(self):
        # First with some small numbers
        self.check_shared(37, 5)

    def test_bignum(self):
        # Now with NIST bignums
        p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
        g = 2

        self.check_shared(p, g)

if __name__ == '__main__':
    unittest.main()

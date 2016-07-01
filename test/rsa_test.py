import unittest
import random
import rsa
from cryptobuffer import cryptobuffer

class rsa_test(unittest.TestCase):

    def setUp(self):
        random.seed()

    def test_mymodexp(self):
        A = rsa.modexp(4, 13, 497)
        self.assertEqual(445, A)

    def test_prime_small(self):
        self.assertTrue(rsa.probably_prime(3))

    def test_prime_big(self):
        self.assertTrue(rsa.probably_prime(4547337172376300111955330758342147474062293202868155909489))

    def test_not_prime_big(self):
        self.assertFalse(rsa.probably_prime(4547337172376300111955330758342147474062293202868155909393))

    def test_modinv(self):
        self.assertEqual(2753, rsa.modinv(17, 3120))

    def test_encrypt_decrypt(self):
        e = 3
        d, n = rsa.gen_key_pair(e)

        print "e = ", e
        print "d = ", d
        print "n = ", n

        m = random.randrange(1, 2 ** 1024)

        print "m = ", m

        c = rsa.encrypt(m, e, n)

        print "c = ", c

        r = rsa.decrypt(c, d, n)

        print "r = ", r

        self.assertEqual(m, r)

    def test_encrypt_decrypt_str(self):
        e = 3
        d, n = rsa.gen_key_pair(e)

        print "e = ", e
        print "d = ", d
        print "n = ", n

        m = "This is a secret message"

        print "m = ", m

        c = rsa.encrypt_str(m, e, n)
        b = cryptobuffer()
        b.mBytes = c

        print "c = ", b.toBase64()

        r = rsa.decrypt_str(c, d, n)

        print "r = ", r

        self.assertEqual(m, r)


if __name__ == '__main__':
    unittest.main()

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

    def test_invpow(self):
        y = rsa.invpow(237734537465873465, 5)
        self.assertEqual(y, 2986)

    def test_broadcast_attack(self):
        e = 3

        # Generate three sets of keys
        d0, n0 = rsa.gen_key_pair(e)
        d1, n1 = rsa.gen_key_pair(e)
        d2, n2 = rsa.gen_key_pair(e)

        m = random.randrange(1, 2 ** 1024)

        c0 = rsa.encrypt(m, e, n0)
        c1 = rsa.encrypt(m, e, n1)
        c2 = rsa.encrypt(m, e, n2)

        ms0 = n1 * n2
        ms1 = n0 * n2
        ms2 = n0 * n1

        n012 = n0 * n1 * n2

        r3 = ((c0 * ms0 * rsa.modinv(ms0, n0)) + \
              (c1 * ms1 * rsa.modinv(ms1, n1)) + \
              (c2 * ms2 * rsa.modinv(ms2, n2))) % n012

        r = rsa.invpow(r3, 3)

        self.assertEqual(m, r)
        
    def test_unpadded_recovery_oracle(self):
        e = 3
        d, n = rsa.gen_key_pair(e)

        # Other message
        m = random.randrange(1, 2 ** 1024)
        # Encrypted result
        c = rsa.encrypt(m, e, n)
        print c

        # The attack: can't decrypt directly
        s = random.randrange(1, 2 ** 1024) % n
        c_dash = (rsa.modexp(s, e, n) * c) % n
        print c_dash
        p_dash = rsa.decrypt(c_dash, d, n)
        p = (p_dash * rsa.modinv(s, n)) % n
        
        self.assertEqual(m, p)

if __name__ == '__main__':
    unittest.main()

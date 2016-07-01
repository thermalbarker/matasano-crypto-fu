import unittest
import random
import rsa

class rsa_test(unittest.TestCase):

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

    

if __name__ == '__main__':
    unittest.main()

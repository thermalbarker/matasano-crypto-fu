import unittest
import random
from diffiehellman import dh_public_key, dh_shared_secret, tom_modexp, dh_encrypt, dh_decrypt
from cryptobuffer import cryptobuffer

class diffiehellman_test(unittest.TestCase):
    # Some NIST BigNums
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    private_key_size = 4294967295

    def test_mymodexp(self):
        A = tom_modexp(4, 13, 497)
        self.assertEqual(445, A)

    def check_shared(self, p, g):
        a = random.randrange(0, self.private_key_size) % p
        A = dh_public_key(p, g, a)

        b = random.randrange(0, self.private_key_size) % p
        B = dh_public_key(p, g, b)

        s_a = dh_shared_secret(p, B, a)
        s_b = dh_shared_secret(p, A, b)

        self.assertEqual(s_a, s_b)

    def test_shared_secret(self):
        # First with some small numbers
        self.check_shared(37, 5)

    def test_bignum(self):
        # Now with NIST bignums
        self.check_shared(self.p, self.g)

    def test_encrypt_decrypt(self):
        p = self.p
        g = self.g
        c = cryptobuffer()

        a = random.randrange(0, self.private_key_size) % p
        A = dh_public_key(p, g, a)

        b = random.randrange(0, self.private_key_size) % p
        B = dh_public_key(p, g, b)
        
        # Encrypted message from a to b
        s_a = dh_shared_secret(p, B, a)
        msg_a_b = c.fromRandomBytes(256)
        iv = c.fromRandomBytes(16)
        cypher_a_b = dh_encrypt(msg_a_b, s_a, iv)

        # Decrypt it with b
        s_b = dh_shared_secret(p, A, b)
        msg_decrypted = dh_decrypt(cypher_a_b, s_b, iv)

        self.assertEqual(msg_a_b, msg_decrypted)

if __name__ == '__main__':
    unittest.main()

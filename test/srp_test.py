import unittest

from srp import SrpServer, SrpClient, ZeroKeyClient

class srp_test(unittest.TestCase):
    # Some NIST BigNums
    N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    k = 2
    user = "tom"
    password = "secret"

    def setUp(self):
        self.server = SrpServer(self.N, self.g, self.k, self.user, self.password)
        self.client = SrpClient(self.N, self.g, self.k, self.user, self.password)

    def test_srp_auth(self):
        # C -> S
        A = self.client.getA()

        # S -> C
        B = self.server.getB()
        salt = self.server.getSalt()

        # C -> S
        auth = self.client.getAuth(B, salt)

        # S -> C
        ok = self.server.checkAuth(A, auth)

        self.assertTrue(ok)

    def srp_auth_try(self, user, password):
        client = SrpClient(self.N, self.g, self.k, user, password)
        # C -> S
        A = client.getA()

        # S -> C
        B = self.server.getB()
        salt = self.server.getSalt()

        # C -> S
        auth = client.getAuth(B, salt)

        # S -> C
        return self.server.checkAuth(A, auth)

    def test_srp_auth_ok(self):
        self.assertTrue(self.srp_auth_try(self.user, self.password))

    def test_srp_bad_password(self):
        self.assertFalse(self.srp_auth_try(self.user, "wrongpassword"))

    def srp_manipulate_key(self, Ain, user, password):
        client = ZeroKeyClient(self.N, self.g, self.k, user, password, Ain)
        # C -> S
        A = client.getA()

        # S -> C
        B = self.server.getB()
        salt = self.server.getSalt()

        # C -> S
        auth = client.getAuth(B, salt)

        # S -> C
        return self.server.checkAuth(A, auth)
        
    def test_srp_zero_key(self):
        self.assertTrue(self.srp_manipulate_key(0, self.user, "wrongpassword"))

    def test_srp_N_key(self):
        self.assertTrue(self.srp_manipulate_key(self.N, self.user, "wrongpassword"))

    def test_srp_2N_key(self):
        self.assertTrue(self.srp_manipulate_key(2 * self.N, self.user, "wrongpassword"))

if __name__ == '__main__':
    unittest.main()

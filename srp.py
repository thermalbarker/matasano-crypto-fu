import random
import hashlib
import hmac

from diffiehellman import dh_public_key, dh_shared_secret, tom_modexp, dh_encrypt, dh_decrypt
from cryptobuffer import cryptobuffer

class SrpCommon(object):
    private_key_size = 2 ** 1024

    def __init__(self, N, g, k, I, P):
        self.N = N # modulus
        self.g = g # exponent
        self.k = k # SRP constant
        self.I = I # username
        self.P = P # password

        p = cryptobuffer()
        p.mBytes = P
        self.pInt = p.toInt()

        self.privkey = random.randrange(0,self.private_key_size) % N

    def get_pub_key(self):
        return dh_public_key(self.N, self.g, self.privkey)

    def hash(self, *args):
        h = hashlib.sha256()
        r = cryptobuffer()
        for a in args:
            b = cryptobuffer()
            b.fromInt(a)
            h.update(b.mBytes)
        r.mBytes = h.digest()
        return r.toInt()

    def computeU(self, A, B):
        return self.hash(A, B)
        
    def computeH(self, salt, p):        
        return self.hash(salt, p)

# Secure remote password
# Challenge 36
class SrpServer(SrpCommon):

    def __init__(self, N, g, k, I, P):
        super(SrpServer, self).__init__(N, g, k, I, P)

        self.salt = random.randint(0, 2 ** 32)
        x = self.computeH(self.salt, self.pInt)

        self.v = tom_modexp(self.g, x, self.N)

    def getB(self):
        return (self.k * self.v + tom_modexp(self.g, self.privkey, self.N)) % self.N

    def getSalt(self):
        return self.salt

    def getU(self, A):
        return self.computeU(A, self.getB())

    def getK(self, A):
        u = self.getU(A)
        b = self.privkey
        S = tom_modexp(A * tom_modexp(self.v, u, self.N), b, self.N)
        K = self.hash(S)
        return K

    def getAuth(self, A, salt):
        K = cryptobuffer()
        K.fromInt(self.getK(A))
        s = cryptobuffer()
        s.fromInt(salt)
        return hmac.new(K.mBytes, s.mBytes, hashlib.sha1).digest()

    def checkAuth(self, A, digest):
        return (self.getAuth(A, self.salt) == digest)

class SrpClient(SrpCommon):

    def __init__(self, N, g, k, I, P):
        super(SrpClient, self).__init__(N, g, k, I, P)

    def getA(self):
        return self.get_pub_key()

    def getI(self):
        return self.I

    def getU(self, B):
        return self.computeU(self.getA(), B)

    def getK(self, salt, B):
        x = self.computeH(salt, self.pInt)
        u = self.getU(B)
        a = self.privkey
        S = tom_modexp(B - self.k * tom_modexp(self.g, x, self.N), a + u * x, self.N)
        K = self.hash(S)
        return K

    def getAuth(self, B, salt):
        K = cryptobuffer()
        K.fromInt(self.getK(salt, B))
        s = cryptobuffer()
        s.fromInt(salt)
        return hmac.new(K.mBytes, s.mBytes, hashlib.sha1).digest()

class ZeroKeyClient(SrpCommon):

    def __init__(self, N, g, k, I, P, A = 0):
        super(ZeroKeyClient, self).__init__(N, g, k, I, P)
        self.A = A

    def getA(self):
        return self.A

    def getI(self):
        return self.I

    def getU(self, B):
        return self.computeU(self.getA(), B)

    def getK(self, salt, B):
        S = 0
        K = self.hash(S)
        return K

    def getAuth(self, B, salt):
        K = cryptobuffer()
        K.fromInt(self.getK(salt, B))
        s = cryptobuffer()
        s.fromInt(salt)
        return hmac.new(K.mBytes, s.mBytes, hashlib.sha1).digest()

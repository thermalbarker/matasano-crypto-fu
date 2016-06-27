import random
import hashlib
import hmac

from diffiehellman import dh_public_key, dh_shared_secret, tom_modexp, dh_encrypt, dh_decrypt
from cryptobuffer import cryptobuffer

class SrpCommon(object):
    private_key_size = 2 ** 1024

    def __init__(self, N, g, k, I, P, privkey = None):
        self.N = N # modulus
        self.g = g # exponent
        self.k = k # SRP constant
        self.I = I # username
        self.P = P # password

        if privkey is None:
            privkey = random.randrange(0, self.private_key_size) % N

        self.privkey = privkey

    def getPint(self):
        p = cryptobuffer()
        p.mBytes = self.P
        return p.toInt()
        
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
        x = self.computeH(self.salt, self.getPint())

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

    def getAuth(self, A):
        K = cryptobuffer()
        K.fromInt(self.getK(A))
        s = cryptobuffer()
        s.fromInt(self.salt)
        return hmac.new(K.mBytes, s.mBytes, hashlib.sha1).digest()

    def checkAuth(self, A, digest):
        return (self.getAuth(A) == digest)

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
        x = self.computeH(salt, self.getPint())
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

# Secure remote password
# Challenge 36
class SrpSimpleServer(SrpCommon):

    def __init__(self, N, g, k, I, P, privkey = None, salt = None, u = None):
        super(SrpSimpleServer, self).__init__(N, g, k, I, P, privkey)

        if salt is None:
            salt = random.randint(0, 2 ** 32)
        if u is None:
            u = random.randint(0, 2 ** 128)
        
        self.setSalt(salt)
        self.setU(u)

    def getB(self):
        return tom_modexp(self.g, self.privkey, self.N)

    def setSalt(self, salt):
        self.salt = salt
        x = self.computeH(self.salt, self.getPint())
        self.v = tom_modexp(self.g, x, self.N)        

    def getSalt(self):
        return self.salt

    def setU(self, u):
        self.u = u

    def getU(self):
        return self.u

    def getK(self, A):
        u = self.getU()
        b = self.privkey
        S = tom_modexp(A * tom_modexp(self.v, u, self.N), b, self.N)
        K = self.hash(S)
        return K

    def getAuth(self, A):
        K = cryptobuffer()
        K.fromInt(self.getK(A))
        s = cryptobuffer()
        s.fromInt(self.salt)
        return hmac.new(K.mBytes, s.mBytes, hashlib.sha1).digest()

    def checkAuth(self, A, digest):
        return (self.getAuth(A) == digest)

class SrpSimpleClient(SrpCommon):

    def __init__(self, N, g, k, I, P):
        super(SrpSimpleClient, self).__init__(N, g, k, I, P)

    def getA(self):
        return self.get_pub_key()

    def getI(self):
        return self.I

    def getK(self, salt, B, u):
        x = self.computeH(salt, self.getPint())
        a = self.privkey
        S = tom_modexp(B, a + u * x, self.N)
        K = self.hash(S)
        return K

    def getAuth(self, B, salt, u):
        K = cryptobuffer()
        K.fromInt(self.getK(salt, B, u))
        s = cryptobuffer()
        s.fromInt(salt)
        return hmac.new(K.mBytes, s.mBytes, hashlib.sha1).digest()


class SrpSimpleDictionaryAttack(object):
    private_key_size = 2 ** 1024

    def __init__(self, filename, N, g, k, I):
        self.d = dict()

        self.N = N
        self.g = g
        self.k = k
        self.I = I

        self.privkey = random.randrange(0, self.private_key_size) % N
        self.salt = random.randint(0, 2 ** 32) 
        self.u = random.randint(0, 2 ** 128) 
         
        self.filename = filename
  
    def CalcHashes(self, A, max = -1):
        self.d.clear()
        infile = open(self.filename, "r")
        i = 0
        for line in infile:
            line = line.rstrip()
            if (line is '') or (line.startswith("#!comment")):
                continue
            server = SrpSimpleServer(self.N, self.g, self.k, self.I, line, self.privkey, self.salt, self.u) 
            m = server.getAuth(A)
            self.d[m] = line
            i += 1
            if (max > 0) and (i >= max):
                break
        infile.close()

    def FindPassword(self, auth):
        return self.d[auth]

    def getB(self):
        return tom_modexp(self.g, self.privkey, self.N)

    def setSalt(self, salt):
        self.salt = salt
        x = self.computeH(self.salt, self.getPint())
        self.v = tom_modexp(self.g, x, self.N)        

    def getSalt(self):
        return self.salt

    def getU(self):
        return self.u

import unittest
import random, time
from twister import twister
from twisteranalysis import twisteranalysis
from mtcypher import mtcypher
from cryptobuffer import cryptobuffer

class twister_test(unittest.TestCase):

    def setUp(self):
        self.t = twister()
        self.a = twisteranalysis()
        random.seed()

    def test_seed(self):
        self.t.set_seed(1)
        r1 = self.t.rand()
        self.t.set_seed(1)
        r2 = self.t.rand()
        print "r1: ", r1, "r2: ", r2
        self.assertEquals(r1, r2)

    def test_rand(self):
        self.t.set_seed(1)
        # Open test values
        infile = open("data/mt_test.txt", "r")
        i = 0
        first = True
        for line in infile:
            # Ignore the first line
            if first:
                first = False
                continue
            for s in line.strip().split():
                r  = int(s)
                r2 = self.t.rand()
                #print "index: ", i, " r = ", hex(r), " r2 = ", hex(r2)
                self.assertEquals(r, r2)
                i += 1
            # There are 200 values for genrand_int32
            if (i >= 200):
                break
        infile.close()
        
    def firstValue(self):
        # Seed with a time in the past
        w1 = time.time() - random.randrange(80,2000)
        print "Seeding with time: ", w1, "s"
        self.t.set_seed(int(w1))
        return self.t.rand()

    def test_crack_seed(self):
        s = self.a.crack_seed(self.firstValue)
        self.assertEquals(s, self.t.seed)

    def test_unrightshift_u(self):
        self.t.set_seed(int(time.time()))
        y = self.t.rand()
        r = y ^ (y >> self.t.u)
        y2 = self.a.unrightshift(r, self.t.u)
        self.assertEquals(y, y2)

    def test_unrightshift_l(self):
        self.t.set_seed(int(time.time()))
        y = self.t.rand()
        r = y ^ (y >> self.t.l)
        y2 = self.a.unrightshift(r, self.t.l)
        self.assertEquals(y, y2)

    def test_unleftshift_sb(self):
        self.t.set_seed(int(time.time()))
        y = self.t.rand()
        r = y ^ ((y << self.t.s) & self.t.b)
        y2 = self.a.unleftshift(r, self.t.s, self.t.b)
        self.assertEquals(y, y2)

    def test_unleftshift_tc(self):
        self.t.set_seed(int(time.time()))
        y = self.t.rand()
        r = y ^ ((y << self.t.t) & self.t.c)
        y2 = self.a.unleftshift(r, self.t.t, self.t.c)
        self.assertEquals(y, y2)

    def test_untemper(self):
        self.t.set_seed(int(time.time()))
        y = self.t.rand()
        x = self.a.untemper(y)
        print
        print "x: ", x, "y: ", y, "mt[0]: ", self.t.mt[0]
        self.assertEquals(x, self.t.mt[0])

    def test_clone(self):
        self.t.set_seed(int(time.time()))
        clone = self.a.clone(self.t)
        for i in range(0, 1000):
            self.assertEquals(self.t.rand(), clone.rand())

    def test_mt_cypher(self):
        key = cryptobuffer()
        key.fromHex('1234')
        mt = mtcypher(key.mBytes)
        plain = cryptobuffer()
        plain.fromFile('data/vanilla.txt')
        encrypted = mt.encrypt(plain.mBytes)
        enplained = mt.decrypt(encrypted)
        self.assertEquals(plain.mBytes, enplained)

    def test_crack_token(self):
        key = cryptobuffer()
        key.fromHex('1234')
        mt = mtcypher(key.mBytes)
        # Generate a token
        pwd = 'AAAAAAAAAAAAAA'
        token = mt.password_token(pwd)
        # Brute force crack it
        result = self.a.crack_oracle(token, pwd)

        self.assertEquals(result, key.mBytes)

    def test_mt_is_timeseeded_true(self):
        mt = mtcypher()
        # Generate a token
        pwd = 'AAAAAAAAAAAAAA'
        token = mt.password_token(pwd)
        self.assertTrue( self.a.is_mt_timeseeded(token, pwd) )

    def test_mt_is_timeseeded_false(self):
        key = cryptobuffer()
        key.fromHex('0101')
        mt = mtcypher(key.mBytes)
        # Generate a token
        pwd = 'AAAAAAAAAAAAAA'
        token = mt.password_token(pwd)
        self.assertFalse( self.a.is_mt_timeseeded(token, pwd) )


if __name__ == '__main__':
    unittest.main()

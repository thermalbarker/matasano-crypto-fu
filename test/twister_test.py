import unittest
import random
from twister import twister

class cryptobuffer_test(unittest.TestCase):

    def setUp(self):
        self.t = twister()

    def test_seed(self):
        self.t.seed(1)
        r1 = self.t.rand()
        self.t.seed(1)
        r2 = self.t.rand()
        print "r1: ", r1, "r2: ", r2
        self.assertEquals(r1, r2)

    def test_rand(self):
        self.t.seed(1)
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
                print "index: ", i, " r = ", hex(r), " r2 = ", hex(r2)
                self.assertEquals(r, r2)
                i += 1
            # There are 1000 values for genrand_int32
            if (i >= 200):
                break
        infile.close()
        

if __name__ == '__main__':
    unittest.main()

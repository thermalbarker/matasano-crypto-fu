import unittest
import random, time
from twister import twister
from twisteranalysis import twisteranalysis

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

if __name__ == '__main__':
    unittest.main()

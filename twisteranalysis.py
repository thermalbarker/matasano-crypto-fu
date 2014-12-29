from twister import twister
import time

class twisteranalysis:

    def crack_seed(self, func):
        r = func()
        print "Random number: ", r
        # The function was seeded up to 2000 seconds in the past
        now = time.time()
        seed = int(now)
        for i in range(0, 2000):
            mt = twister()
            seed = int(now - i)
            mt.set_seed(seed)
            my_r = mt.rand()
            if (my_r == r):
                print "Found seed: ", seed
                break

        return seed

    def untemper(self, y):
        mt = twister()
        x = y & 0xFFFFFFFF
        x = self.unrightshift(x, mt.l)
        x = self.unleftshift(x, mt.t, mt.c)
        x = self.unleftshift(x, mt.s, mt.b)
        x = self.unrightshift(x, mt.u)
        return x
    
    def unrightshift(self, y, shift):
        # And the 'shift' bits 0, upper bits 1
        upper = (0xFFFFFFFF << (32 - shift)) & 0xFFFFFFFF
        lower = (0xFFFFFFFF >> shift) & 0xFFFFFFFF
        print '\nupper      ', '{0:32b}'.format(upper)
        print 'lower      ', '{0:32b}'.format(lower)
        return (y & upper) | (((y >> shift) ^ y) & lower)
                     
    def unleftshift(self, y, shift, mask):
        m  = mask & 0xFFFFFFFF
        nm =   ~m & 0xFFFFFFFF
        upper =  0xFFFFFFFF << shift
        lower = (0xFFFFFFFF >> (32 - shift)) & 0xFFFFFFFF
        r = (((y << shift) & m) ^ y) & upper  | \
             (y & upper & nm)                 | \
             (y & lower)
        return r

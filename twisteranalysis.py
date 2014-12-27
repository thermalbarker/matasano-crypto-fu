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
                     

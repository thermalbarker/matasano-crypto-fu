from twister import twister
import time

class twisteranalysis:

    allbits = 0xFFFFFFFF

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

    def clone(self, mt):
        clone = twister()
        a = [0] * mt.n
        # Untemper each number in the sequence
        for i in range(0, mt.n):
            y = mt.rand()
            a[i] = self.untemper(y)
        # Graft the states onto the clone
        clone.mt = a
        return clone

    def untemper(self, y):
        mt = twister()
        x = y & 0xFFFFFFFF
        x = self.unrightshift(x, mt.l)
        x = self.unleftshift(x, mt.t, mt.c)
        x = self.unleftshift(x, mt.s, mt.b)
        x = self.unrightshift(x, mt.u)
        return x
    
    def unrightshift(self, y, shift):
        i = 0
        result = 0
        while i * shift < 32:
            # Create a mask for this part
            partMask = ((self.allbits << (32 - shift)) & self.allbits) >> (shift * i)
            # Obtain the part
            part = y & partMask
            # Unapply the XOR operation from the integer
            y ^= part >> shift
            # Add to the result
            result |= part
            i += 1
        return result
            
                     
    def unleftshift(self, y, shift, mask):
        i = 0
        result = 0
        while i * shift < 32:
            # Create a mask for this part
            partMask = ((self.allbits >> (32 - shift)) & self.allbits) << (shift * i)
            # Obtain the part
            part = y & partMask
            # Unapply the XOR operation from the integer
            y ^= (part << shift) & mask
            # Add to the result
            result |= part
            i += 1
        return result


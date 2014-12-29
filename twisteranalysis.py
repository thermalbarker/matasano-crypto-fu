from twister import twister
from cryptobuffer import cryptobuffer
from mtcypher import mtcypher
import time

class twisteranalysis:

    allbits = 0xFFFFFFFF

    def crack_seed(self, func):
        r = func()
        print "Brute force cracking MT seed"
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

    # From https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html
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
            
    # From https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html                     
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


    def crack_oracle(self, token_in, pwd_in):
        token = cryptobuffer()
        key = cryptobuffer()
        pwd = cryptobuffer()
        n = len(pwd_in)
        pwd.fromString(pwd_in)
        token.mBytes = token_in

        print "Brute force attack on MT cypher"
        print "Token: ", token.toBase64()
        preamble_len = len(token.mBytes) - len(pwd.mBytes)
        for k in range(0, 2 << 16):
            key.fromInt(k)
            mt = mtcypher(key.mBytes, preamble_len)
            enc_try = mt.password_token(pwd.toString())
            # Check the last n characters
            if (enc_try[-n:-1] == token.mBytes[-n:-1]):
                print "...Found match using key: ", key.toHex()
                break

        return key.mBytes

    def is_mt_timeseeded(self, token_in, pwd_in):
        # Take the time before any cracking is done
        now = int(time.time()) & 0xFFFF

        key = cryptobuffer()
        key.mBytes = self.crack_oracle(token_in, pwd_in)
        key_int = key.toInt()

        # Check if the seed was generated recently
        return ((now - key_int) < 300)
        

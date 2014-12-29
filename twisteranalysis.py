from twister import twister
from cryptobuffer import cryptobuffer
from mtcypher import mtcypher
import time, copy, math

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
    def clone(self, rands):
        clone = twister()
        # Untemper each number in the sequence
        for i in range(0, clone.n):
            clone.mt[i] = self.untemper(rands[i])

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


    # Rewind a twister by n
    def rewind_twister(self, mt, n):
        # How many time to rewind the internal state
        blocks = abs((mt.index - n) // mt.n)
        # The index within that state
        bindex = (mt.index - n) % mt.n
        clone = twister()
        clone.mt = mt.mt[:]
        clone.index = mt.index
        if blocks:
            for i in range(0, blocks):
                clone = self.rewind_twister_block(clone)
        clone.index = bindex
        return clone

    # Rewind the MT to the previous state
    # https://jazzy.id.au/2010/09/25/cracking_random_number_generators_part_4.html
    def rewind_twister_block(self, mt):
        clone = twister()
        clone.index = mt.index
        clone.mt = mt.mt[:]
        for i in reversed(range(clone.n)):
            result = 0
            # Calculate the first bit
            tmp = clone.mt[i]
            tmp ^=  clone.mt[ (i + clone.m) % clone.n ]
            # if the first bit is odd, unapply magic
            if ((tmp & clone.mask2) == clone.mask2):
                tmp ^= clone.a
            # the second bit of tmp is the first bit of the result
            result = (tmp << 1) & clone.mask2

            # work out the remaining 31 bits
            tmp  = clone.mt[(i - 1 + clone.n) % clone.n];
            tmp ^= clone.mt[(i - 1 + clone.m) % clone.n];
            if ((tmp & clone.mask2) == clone.mask2):
                tmp ^= clone.a
                # since it was odd, the last bit must have been 1
                result |= 1
            # extract the final 30 bits
            result |= (tmp << 1) & clone.mask3
            clone.mt[i] = result

        return clone


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
        

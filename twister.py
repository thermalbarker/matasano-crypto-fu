import time

# From wikipedia http://en.wikipedia.org/wiki/Mersenne_twister
class twister():

    n = 624
    m = 397

    k = 1812433253
    a = 2567483615
    u = 11
    s = 7
    b = 2636928640
    t = 15
    c = 4022730752
    l = 18

    mask1 = 0xFFFFFFFF
    mask2 = 0x80000000
    mask3 = 0x7FFFFFFF

    index = 0

    def __init__(self):
        self.mt = [0] * self.n
        self.index  = 0
        self.seed()

    # Initilise the generator with a seed
    # default as used by MT creators
    def seed(self, seed = 5489):
        self.index = 0
        self.mt[0] = seed & self.mask1
        for i in range(1, self.n):
            self.mt[i] = (self.k * (self.mt[i-1] ^ (self.mt[i-1] >> 30)) + i)
            self.mt[i] &= self.mask1
    def seed_time(self):
        self.seed( int(time.time()) )

    # Generate array of 624 untempered numbers
    def generate_numbers(self):
        for i in range(0, self.n):
            y = (self.mt[i] & self.mask2) + (self.mt[ (i+1) % self.n ] & self.mask3)

            self.mt[i] = self.mt[ (i + self.m) % self.n ] ^ (y >> 1)

            if ((y % 2) != 0): # y is odd
                self.mt[i] ^= self.a

    # Extract a tempered random number based in the index-th value
    # calling generate numbers every 624 numbers
    def rand(self):
        if (self.index == 0):
            self.generate_numbers()

        y = self.mt[ self.index ]
        y ^= (y >> self.u)
        y ^= (y << self.s) & self.b
        y ^= (y << self.t) & self.c
        y ^= (y >> self.l)
        self.index = (self.index + 1) % self.n

        return y
        

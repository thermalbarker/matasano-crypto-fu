
class sha1():

    # Pseudo-code from http://en.wikipedia.org/wiki/SHA-1
    # Note 1: All variables are unsigned 32 bits and wrap modulo 232 when calculating, except
    #    ml the message length which is 64 bits, and
    #    hh the message digest which is 160 bits.
    # Note 2: All constants in this pseudo code are in big endian.
    #    Within each word, the most significant byte is stored in the leftmost byte position

    # Initialize variables:

    i0 = 0x67452301
    i1 = 0xEFCDAB89
    i2 = 0x98BADCFE
    i3 = 0x10325476
    i4 = 0xC3D2E1F0

    lchunk = 512 / 8

    def rol(self, val, r_bits, max_bits = 32):
        return (val << r_bits%max_bits) & (2**max_bits-1) | \
        ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

    def chunks(self, l, n):
        """ Yield successive n-sized chunks from l.
        """
        for i in xrange(0, len(l), n):
            yield l[i:i+n]

#    ml = message length in bits (always a multiple of the number of bits in a character).

#Pre-processing:
#append the bit '1' to the message i.e. by adding 0x80 if characters are 8 bits. 
#append 0 . k < 512 bits '0', thus the resulting message length (in bits)
#   is congruent to 448 (mod 512)
#append ml, in a 64-bit big-endian integer. So now the message length is a multiple of 512 bits.

    def pre_process(self, message):
        

    # Process the message in successive 512-bit chunks:
    def do_hash(self, message):

        h0 = self.i0
        h1 = self.i1
        h2 = self.i2
        h3 = self.i3
        h4 = self.i4

        # break message into 512-bit chunks
        for chunk in self.chunks(message, self.lchunk):
            w = []
            # break chunk into sixteen 32-bit big-endian words w[i], 0 . i . 15
            for x in self.chunks(chunk, 4):
                # Convert to 32-bit int
                w.append( int(x.encode('hex'), 8) )
            # Extend the sixteen 32-bit words into eighty 32-bit words:
            for i in range(16, 80):
                w.append( rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1) )
            
            # Initialize hash value for this chunk:
            a = h0
            b = h1
            c = h2
            d = h3
            e = h4

            # Main loop:[42]
            for i in range(0, 80):
                if 0 < i <= 19:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 < i <= 39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 < i <= 59:
                    f = (b & c) | (b & d) | (c & d) 
                    k = 0x8F1BBCDC
                elif 60 < i <= 79:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6

                    temp = (rol(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
                e = d
                d = c
                c = rol(b, 30)
                b = a
                a = temp

            #  Add this chunk's hash to result so far:
            h0 = (h0 + a) & 0xFFFFFFFF
            h1 = (h1 + b) & 0xFFFFFFFF
            h2 = (h2 + c) & 0xFFFFFFFF
            h3 = (h3 + d) & 0xFFFFFFFF
            h4 = (h4 + e) & 0xFFFFFFFF

        # Produce the final hash value as a 160 bit int
        hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) |  h4
        return hh
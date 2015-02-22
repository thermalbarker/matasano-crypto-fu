import binascii

class hash():

    bits_in_a_byte = 8
    chunk_bits  = 512
    len_bits = 64

    def rotateleft(self, val, r_bits, max_bits = 32):
        return (val << r_bits%max_bits) & (2**max_bits-1) | \
        ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

    def chunks(self, l, n):
        """ Yield successive n-sized chunks from l.
        """
        for i in xrange(0, len(l), n):
            yield l[i:i+n]

    def chunk_bytes(self):
        return self.chunk_bits / self.bits_in_a_byte

    def len_bytes(self):
        return self.len_bits / self.bits_in_a_byte

    def get_padding(self, length):
        padding = bytearray()
        # Calculate 64-bit message length as a bytearray
        # Format string in hex characters - 2 hex chars per byte
        fmt = '%%0%dx' % (self.len_bytes() * 2) 
        # Write the length (in bits) into a 64-bit bytearray
        ml = binascii.unhexlify( fmt % (length * self.bits_in_a_byte) )
        # Append the bit '1' to the message i.e. by adding 0x80 if characters are 8 bits. 
        padding.append(0x80)
        # Append 0 < k < 512 bits '0', thus the resulting message length (in bits)
        # is congruent to 448 (mod 512)
        bytes_to_add = (self.chunk_bytes() - self.len_bytes()) - \
                       ((length + len(padding)) % self.chunk_bytes())
        #               512 bits           - 64 bits         
        padding.extend( bytearray( bytes_to_add ) )
        # Append ml, in a 64-bit big-endian integer.
        # So now the message length is a multiple of 512 bits.
        padding.extend(ml)

        return padding        

    def pre_process(self, message):        
        """  Pre-processing
        """
        # Make a copy of the message
        padded = bytearray()
        padded[:] = message
        padded.extend( self.get_padding(len(message)) )

        return padded

    def digest(self, message):
        padded = self.pre_process(message)
        return self.do_hash(padded, self.magic)

    def extend_hash(self, current_sha1, message):
        i = []
        # break chunk into five 32-bit big-endian words w[i], 0 . i . 15
        for x in self.chunks(current_sha1, 4):
            # Convert to 32-bit int
            i.append( int(binascii.hexlify(x), 16) )
        return self.do_hash(message, i)


    def keyed_mac(self, key, message):
        cat = bytearray()
        cat[:] = key
        cat.extend(message)
        return self.digest(cat)

class fixed_key():

    def __init__(self, key, algo):
        self.key = key
        self.algo = algo

    def calc_sha1_fixed_key(message):
        return self.algo.keyed_mac(self.key, message)


class sha1(hash):
    """ Pseudo-code from http://en.wikipedia.org/wiki/SHA-1
    Note 1: All variables are unsigned 32 bits and wrap modulo 232 when calculating, except
    ml the message length which is 64 bits, and
    hh the message digest which is 160 bits.
    Note 2: All constants in this pseudo code are in big endian.
    Within each word, the most significant byte is stored in the leftmost byte position
    """

    # Initialize variables:

    magic = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

    def do_hash(self, message, i):
        """ Process the message in successive 512-bit chunks:
        """
        hh = bytearray()
        h0 = i[0]
        h1 = i[1]
        h2 = i[2]
        h3 = i[3]
        h4 = i[4]
        
        # break message into 512-bit chunks
        for chunk in self.chunks(message, self.chunk_bytes()):
            w = []
            # break chunk into sixteen 32-bit big-endian words w[i], 0 . i . 15
            for x in self.chunks(chunk, 4):
                # Convert to 32-bit int
                w.append( int(binascii.hexlify(x), 16) )
            # Extend the sixteen 32-bit words into eighty 32-bit words:
            for i in range(16, 80):
                w.append( self.rotateleft(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1) )
            
            # Initialize hash value for this chunk:
            a = h0
            b = h1
            c = h2
            d = h3
            e = h4
            f = 0
            k = 0

            # Main loop:
            for i in range(0, 80):
                if 0 <= i <= 19:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 <= i <= 39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= i <= 59:
                    f = (b & c) | (b & d) | (c & d) 
                    k = 0x8F1BBCDC
                elif 60 <= i <= 79:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6

                temp = (self.rotateleft(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
                e = d
                d = c
                c = self.rotateleft(b, 30)
                b = a
                a = temp

            #  Add this chunk's hash to result so far:
            h0 = (h0 + a) & 0xFFFFFFFF
            h1 = (h1 + b) & 0xFFFFFFFF
            h2 = (h2 + c) & 0xFFFFFFFF
            h3 = (h3 + d) & 0xFFFFFFFF
            h4 = (h4 + e) & 0xFFFFFFFF

        # Produce the final hash value as a 160 bit int
        hh.extend( binascii.unhexlify( '%08x' % h0 ))
        hh.extend( binascii.unhexlify( '%08x' % h1 ))
        hh.extend( binascii.unhexlify( '%08x' % h2 ))
        hh.extend( binascii.unhexlify( '%08x' % h3 ))
        hh.extend( binascii.unhexlify( '%08x' % h4 ))

        return hh


class md4(hash):
    
    magic = [0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 ]

    def f(self, x, y, z):
        return (x & y) | ((~x) & z)

    def g(self, x, y, z):
        return (x & y) | (x & z) | (y & z)

    def h(self, x, y, z):
        return x ^ y ^ z

    def round1(self, a, b, c, d, k, s, X):
        return self.rotateleft( a + self.f(b, c, d) + X[k], s )

    def round2(self, a, b, c, d, k, s, X):
        return self.rotateleft( a + self.g(b, c, d) + X[k] + 0x5a827999, s )

    def round3(self, a, b, c, d, k, s, X):
        return self.rotateleft( a + self.h(b, c, d) + X[k] + 0x6ed9eba1, s )


    def do_hash(self, message, i):
        """ Process the message in successive 512-bit chunks:
        """

        hh = bytearray()
        A = i[0]
        B = i[1]
        C = i[2]
        D = i[3]
        
        # break message into 512-bit chunks
        for chunk in self.chunks(message, self.chunk_bytes()):
            X = []
            # break chunk into sixteen 32-bit big-endian words w[i], 0 . i . 15
            for x in self.chunks(chunk, 4):
                # Convert to 32-bit int
                X.append( int(binascii.hexlify(x), 16) )
            
            # Initialize hash value for this chunk:
            AA = A
            BB = B
            CC = C
            DD = D

            # Round 1
            A = self.round1(A, B, C, D,  0,  3, X) 
            D = self.round1(D, A, B, C,  1,  7, X)
            C = self.round1(C, D, A, B,  2, 11, X)
            B = self.round1(B, C, D, A,  3, 19, X)
            A = self.round1(A, B, C, D,  4,  3, X)
            D = self.round1(D, A, B, C,  5,  7, X)
            C = self.round1(C, D, A, B,  6, 11, X)
            B = self.round1(B, C, D, A,  7, 19, X)
            A = self.round1(A, B, C, D,  8,  3, X)
            D = self.round1(D, A, B, C,  9,  7, X)
            C = self.round1(C, D, A, B, 10, 11, X)
            B = self.round1(B, C, D, A, 11, 19, X)
            A = self.round1(A, B, C, D, 12,  3, X)
            D = self.round1(D, A, B, C, 13,  7, X)
            C = self.round1(C, D, A, B, 14, 11, X)
            B = self.round1(B, C, D, A, 15, 19, X)

            # Round 2
            A = self.round2(A, B, C, D,  0,  3, X)
            D = self.round2(D, A, B, C,  4,  5, X)
            C = self.round2(C, D, A, B,  8,  9, X)
            B = self.round2(B, C, D, A, 12, 13, X)
            A = self.round2(A, B, C, D,  1,  3, X)
            D = self.round2(D, A, B, C,  5,  5, X)
            C = self.round2(C, D, A, B,  9,  9, X)
            B = self.round2(B, C, D, A, 13, 13, X)
            A = self.round2(A, B, C, D,  2,  3, X)
            D = self.round2(D, A, B, C,  6,  5, X)
            C = self.round2(C, D, A, B, 10,  9, X)
            B = self.round2(B, C, D, A, 14, 13, X)
            A = self.round2(A, B, C, D,  3,  3, X)
            D = self.round2(D, A, B, C,  7,  5, X)
            C = self.round2(C, D, A, B, 11,  9, X)
            B = self.round2(B, C, D, A, 15, 13, X)

            # Round 3
            A = self.round3(A, B, C, D,  0,  3, X)
            D = self.round3(D, A, B, C,  8,  9, X)
            C = self.round3(C, D, A, B,  4, 11, X)
            B = self.round3(B, C, D, A, 12, 15, X)
            A = self.round3(A, B, C, D,  2,  3, X)
            D = self.round3(D, A, B, C, 10,  9, X)
            C = self.round3(C, D, A, B,  6, 11, X)
            B = self.round3(B, C, D, A, 14, 15, X)
            A = self.round3(A, B, C, D,  1,  3, X)
            D = self.round3(D, A, B, C,  9,  9, X)
            C = self.round3(C, D, A, B,  5, 11, X)
            B = self.round3(B, C, D, A, 13, 15, X)
            A = self.round3(A, B, C, D,  3,  3, X)
            D = self.round3(D, A, B, C, 11,  9, X)
            C = self.round3(C, D, A, B,  7, 11, X)
            B = self.round3(B, C, D, A, 15, 15, X)

            A = (A + AA) & 0xFFFFFFFF
            B = (B + BB) & 0xFFFFFFFF
            C = (C + CC) & 0xFFFFFFFF
            D = (D + DD) & 0xFFFFFFFF

        # Produce the final hash value bytearray
        hh.extend( binascii.unhexlify( '%08x' % A ))
        hh.extend( binascii.unhexlify( '%08x' % B ))
        hh.extend( binascii.unhexlify( '%08x' % C ))
        hh.extend( binascii.unhexlify( '%08x' % D ))

        return hh
import binascii


class sha1():
    """ Pseudo-code from http://en.wikipedia.org/wiki/SHA-1
    Note 1: All variables are unsigned 32 bits and wrap modulo 232 when calculating, except
    ml the message length which is 64 bits, and
    hh the message digest which is 160 bits.
    Note 2: All constants in this pseudo code are in big endian.
    Within each word, the most significant byte is stored in the leftmost byte position
    """

    # Initialize variables:

    i0 = 0x67452301
    i1 = 0xEFCDAB89
    i2 = 0x98BADCFE
    i3 = 0x10325476
    i4 = 0xC3D2E1F0

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

    def pre_process(self, message):        
        """  Pre-processing
        """
        # Make a copy of the message
        padded = bytearray()
        padded[:] = message
        # Calculate 64-bit message length as a bytearray
        # Format string in hex characters - 2 hex chars per byte
        fmt = '%%0%dx' % (self.len_bytes() * 2) 
        # Write the length (in bits) into a 64-bit bytearray
        ml = binascii.unhexlify( fmt % (len(message) * self.bits_in_a_byte) )
        # Append the bit '1' to the message i.e. by adding 0x80 if characters are 8 bits. 
        padded.append(0x80)
        # Append 0 < k < 512 bits '0', thus the resulting message length (in bits)
        # is congruent to 448 (mod 512)
        bytes_to_add = (self.chunk_bytes() - self.len_bytes()) - (len(padded) % self.chunk_bytes())
        #               512 bits           - 64 bits         
        padded.extend( bytearray( bytes_to_add ) )
        # Append ml, in a 64-bit big-endian integer.
        # So now the message length is a multiple of 512 bits.
        padded.extend(ml)

        return padded


    def do_hash(self, message):
        """ Process the message in successive 512-bit chunks:
        """

        hh = bytearray()

        h0 = self.i0
        h1 = self.i1
        h2 = self.i2
        h3 = self.i3
        h4 = self.i4

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

    def calc_sha1(self, message):
        padded = self.pre_process(message)
        return self.do_hash(padded)

    def sha1_keyed_mac(self, key, message):
        cat = bytearray()
        cat[:] = key
        cat.extend(message)
        return self.calc_sha1(cat)

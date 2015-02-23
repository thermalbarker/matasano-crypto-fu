from hash import hash
from cryptobuffer import cryptobuffer
import time, operator

class hash_break():

    def __init__(self, algo):
        self.algo = algo

    def extend_hash(self, original_hash, original_message, new_message, verify_func, max_key_length = 64):

        for k in range(1, max_key_length):
            original_padding = self.algo.get_padding( len(original_message) + k )
            total_message = bytearray()
            total_message.extend(original_message)
            total_message.extend(original_padding)
            total_message.extend(new_message)

            new_padding = self.algo.get_padding( len(new_message), len(total_message) + k )

            extended_message = bytearray()
            extended_message.extend(new_message)
            extended_message.extend(new_padding)
            
            new_hash = self.algo.extend_hash( original_hash, extended_message )

            if (verify_func( total_message, new_hash )):
                return (total_message, new_hash)

        return (None, None)

    def timing_leak_attack(self, compare_func, message, max_len = 20):
        hmac = cryptobuffer()
        
        for i in range(0, max_len):
            d = {}
            hmac.mBytes.append(0)
            mean = 0.0
            for c in range(0, 256):
                hmac.mBytes[i] = c
                start = time.time()
                compare_func(message, hmac)
                elapsed = time.time() - start
                #print "   Trying: ", hmac.toHex()
                #print "   Time:   ", elapsed, " ms"
                d[c] = elapsed
                mean += elapsed
            longest_c = max(d.iteritems(), key=operator.itemgetter(1))[0]
            mean /= float(len(d))
            hmac.mBytes[i] = longest_c 
            print "i:", i, "Char: ", longest_c, "Time: ", d[longest_c], "Mean: ", mean 
            print "Current hmac: ", hmac.toHex()

        return hmac.mBytes

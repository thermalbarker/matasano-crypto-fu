from hash import hash
from cryptobuffer import cryptobuffer
import time, operator, statistics, math

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

    def timing_leak_attack(self, compare_func, message, max_len = 32):
        hmac = cryptobuffer()
        total_start = time.time()

        for i in range(0, max_len):
            d = {}
            hmac.mBytes.append(0)

            print "Byte:", i

            longest_c = 0

            for c in range(0, 256):
                hmac.mBytes[i] = c
                start = time.time()
                compare_func(message, hmac)
                elapsed = time.time() - start
                d[c] = elapsed

            # Get the char with the longest time
            longest_c = max(d.iteritems(), key=operator.itemgetter(1))[0]
            signal = d[longest_c]
            
            hmac.mBytes[i] = longest_c

            print "  Char: ", format(hex(longest_c)), "Time: ", d[longest_c]
            print "  Current hmac: ", hmac.toHex()
            print "  Total time: ", time.time() - total_start

            if (compare_func(message, hmac)):
                print "--> Valid Hmac! Exiting!"
                break

        return hmac.mBytes


    def timing_leak_attack2(self, compare_func, message, stdevs = 5, max_len = 32, max_runs = 100):
        hmac = cryptobuffer()
        total_start = time.time()
        average = statistics.median

        for i in range(0, max_len):
            d = {}
            aves = {}
            hmac.mBytes.append(0)

            print "Byte:", i

            for c in range(0,256):
                d[c] = []
            longest_c = -1

            for j in range(0, max_runs):

                for c in range(0, 256):
                    hmac.mBytes[i] = c
                    start = time.time()
                    compare_func(message, hmac)
                    elapsed = time.time() - start
                    d[c].append( elapsed )
                    aves[c] = average( d[c] )

                    # Assume c is the signal, calculate significance
                    bg = []
                    for k in range(0, 256):
                        a = d[k]
                        if (k != c):
                            bg.extend(a)
                    if ((len(bg) < 2) or (len(d[c]) < 2)):
                        continue
                    bg_ave = average(bg)
                    bg_stdev = statistics.stdev(bg)
                    sg_ave = average(d[c])
                    sg_stdev = statistics.stdev(d[c])
                    
                    diff = (sg_ave - bg_ave) / bg_stdev
                    diff_err = math.sqrt( (sg_stdev**2)/len(d[c]) + (bg_stdev**2)/len(bg) ) / bg_stdev

                    if (diff > stdevs) and (diff_err < 1.0):
                        longest_c = c

                        print "    char:  ", format(hex(c))
                        print "    x_bar(bg):", bg_ave, "sigma(bg):", bg_stdev/bg_ave, "n(bg):", len(bg)
                        print "    x_bar(sg):", sg_ave, "sigma(sg):", sg_stdev/aves[c], "n(sg):", len(d[c])
                        print "    n_sigma:", diff, "+/-", diff_err

                        print "      --> Difference >", stdevs, "sigma, stopping!"
                        break

                if (longest_c >= 0):
                    break

            hmac.mBytes[i] = longest_c

            print "  Char: ", longest_c, "Time: ", aves[longest_c]
            print "  Current hmac: ", hmac.toHex()
            print "  Total time: ", time.time() - total_start

            if (compare_func(message, hmac)):
                print "--> Valid Hmac! Exiting!"
                break

        return hmac.mBytes

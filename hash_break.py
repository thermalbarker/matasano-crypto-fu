from hash import hash
from cryptobuffer import cryptobuffer
import time, operator, statistics, math
#from text_histogram import histogram

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

    def timing_leak_attack(self, compare_func, message, max_len = 32, stop_at_bytes = -1):
        hmac = cryptobuffer()
        total_start = time.time()

        print "Simple timing leak attack on SHA1"

        for i in range(0, max_len):
            d = {}
            hmac.mBytes.append(0)

            print "Byte:", i

            success = False
            longest_c = -1

            for c in range(0, 256):
                hmac.mBytes[i] = c
                start = time.time()
                success = compare_func(message, hmac)
                elapsed = time.time() - start
                d[c] = elapsed * 1000.0
                
                # If we have found a valid hash, no need to keep searching
                if (success):
                    longest_c = c
                    break

            # Get the char with the longest time
            if (not success):
                longest_c = max(d.iteritems(), key=operator.itemgetter(1))[0]

            signal = d[longest_c]            
            hmac.mBytes[i] = longest_c

            print "  Char: ", format(hex(longest_c)), "Time: ", d[longest_c]
            print "  Current hmac: ", hmac.toHex()
            print "  Total time: ", time.time() - total_start

            if (compare_func(message, hmac)):
                print "--> Valid Hmac! Exiting!"
                break


            if ((stop_at_bytes > 0) and (len(hmac.mBytes) >= stop_at_bytes)):
                print "Exiting early, found:", stop_at_bytes, "bytes"
                break


        return hmac.mBytes


    def timing_leak_attack2(self, compare_func, message, max_len = 32, stop_at_bytes = -1, stdevs = 5, max_runs = 100):
        hmac = cryptobuffer()
        total_start = time.time()
        average = statistics.median

        print "Statistical timing leak attack on SHA1"

        for i in range(0, max_len):
            d = {}
            aves = {}
            p = []
            hmac.mBytes.append(0)

            print "Byte:", i

            for c in range(0,256):
                d[c] = []
            longest_c = -1
            best_c = -1

            for j in range(0, max_runs):
                success = False

                for c in range(0, 256):
                    hmac.mBytes[i] = c
                    start = time.time()
                    success = compare_func(message, hmac)
                    elapsed = (time.time() - start) * 1000.0
                    d[c].append( elapsed )
                    p.append( elapsed )
                    aves[c] = average( d[c] )

                    # If we are successful, no need for analysis!
                    if (success):
                        longest_c = c
                        break

                    # Assume c is the signal, calculate significance
                    bg = []
                    for k in range(0, 256):
                        a = d[k]
                        if (k != c):
                            bg.extend(a)
                    if ((len(bg) < 2) or (len(d[c]) < 2)):
                        continue
                    bg_n   = len(bg)
                    bg_ave = average(bg)
                    bg_stdev = statistics.stdev(bg)
                    sg_n   = len(d[c])
                    sg_ave = average(d[c])
                    sg_stdev = statistics.stdev(d[c])
                    
                    diff = (sg_ave - bg_ave) / bg_stdev
                    diff_err = math.sqrt( sg_stdev**2/sg_n + bg_stdev**2/bg_n ) / bg_stdev

                    if ((diff - diff_err) > stdevs):
                        longest_c = c

                        print "    char:  ", format(hex(c))
                        print "    x_bar(bg):", bg_ave, "sigma(bg):", bg_stdev, "n(bg):", len(bg)
                        print "    x_bar(sg):", sg_ave, "sigma(sg):", sg_stdev, "n(sg):", len(d[c])
                        print "    n_sigma:", diff, "+/-", diff_err
                        
                        print "      --> Difference >", stdevs, "sigma, stopping!"
                        break


#                if (len(p) > 1):
#                    histogram( p, None, None, 50 )                                       

                if (longest_c >= 0):
                    break
            
            if (longest_c >= 0):
                hmac.mBytes[i] = longest_c
            else:
                hmac.mBytes[i] = best_c

            print "  Char: ", longest_c, "Time: ", aves[longest_c]
            print "  Current hmac: ", hmac.toHex()
            print "  Total time: ", time.time() - total_start

            if (compare_func(message, hmac)):
                print "--> Valid Hmac! Exiting!"
                break

            if ((stop_at_bytes > 0) and (len(hmac.mBytes) >= stop_at_bytes)):
                print "Exiting early, found:", stop_at_bytes, "bytes"
                break


        return hmac.mBytes

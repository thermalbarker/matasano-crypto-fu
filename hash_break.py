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

    def timing_leak_attack(self, compare_func, message, stdevs = 3, max_len = 32, max_runs = 100):
        hmac = cryptobuffer()
        total_start = time.time()

        # Use the median rather than mean
        # as it is less sensitive to outliers
        average = statistics.median

        for i in range(0, max_len):
            d = {}
            aves = {}
            hmac.mBytes.append(0)

            print "Byte:", i

            for c in range(0,256):
                d[c] = []
            longest_c = 0

            for j in range(0, max_runs):
                if (j > 0):
                    print "  Iteration: ", j

                for c in range(0, 256):
                    hmac.mBytes[i] = c
                    start = time.time()
                    compare_func(message, hmac)
                    elapsed = time.time() - start
                    d[c].append( elapsed )
                    aves[c] = average( d[c] )

                # Need two iterations to get a stdev
                if (j < 1): continue

                # Get the char with the longest time
                longest_c = max(aves.iteritems(), key=operator.itemgetter(1))[0]
                signal = aves[longest_c]
                
                # Make a copy of the list without the longest value
                background = dict(aves)

                # Delete the 'signal'
                del background[longest_c]

                # Calculate the mean background
                mean = average(background.values())

                # Get the statistical fluctualtion on the max value
                # NB: need two tries
                if (j > 0):
                    stdev = statistics.stdev(d[longest_c])
                else:
                    stdev = 1000.0

                # See how many standard deviations the largest value is from the mean
                diff = (signal - mean) / stdev

                print "    Best Signal: ", format(hex(longest_c))
                print "    Background: ", mean, "Signal: ", signal
                print "    Stdev: ", stdev, "Diff: ", diff

                if (diff > stdevs):
                    print "      --> Difference >", stdevs, "sigma, stopping!"
                    break

            hmac.mBytes[i] = longest_c

            print "  Char: ", longest_c, "Time: ", aves[longest_c]
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
                    diff_err = math.sqrt( (sg_stdev/len(d[c])**2 + (bg_stdev/len(bg))**2) )

                    if (diff > stdevs) and (diff_err < 1.0):
                        longest_c = c

                        print "    char:  ", format(hex(c))
                        print "    n(bg): ", len(bg), "x_bar(bg):", bg_ave, "sigma(bg):", bg_stdev/bg_ave
                        print "    n(sg): ", len(d[c]), "x_bar(sig):", sg_ave, "sigma(sg):", sg_stdev/aves[c],
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

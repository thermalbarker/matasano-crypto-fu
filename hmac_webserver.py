from hash import fixed_key_hash, sha1
import random, time

class server():

    def __init__(self, algo = sha1(), timing = 50, length = 32):
        random.seed()
        self.timing = float(timing) / 1000.0
        key = bytearray(length)
        for i in range(0, length):
            key[i] = random.randrange(256)
        self.algo = fixed_key_hash(key, algo)

    def insecure_compare(self, message, hmac):
        expected_hmac = self.algo.hmac(message)

        for i in range(0, len(expected_hmac)):
            time.sleep(self.timing)

            if (i >= len(hmac)):
                return False
            if (hmac[i] != expected_hmac[i]):
                return False


        return True

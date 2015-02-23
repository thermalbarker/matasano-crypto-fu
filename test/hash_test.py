import unittest
import random
from cryptobuffer import cryptobuffer
from hash import sha1, md4, hash, fixed_key_hash
from hmac_webserver import server

from hash_break import hash_break

class hash_test(unittest.TestCase):

    def setUp(self):
        self.myHash = hash()

    def test_padding(self):
        message = cryptobuffer()
        padding = cryptobuffer()

        message.fromHex('FFFF')
        padding.mBytes = self.myHash.pre_process(message.mBytes)

        # Expected padding:
        padded = 'ffff800000000000' + \
                 '0000000000000000' + \
                 '0000000000000000' + \
                 '0000000000000000' + \
                 '0000000000000000' + \
                 '0000000000000000' + \
                 '0000000000000000' + \
                 '0000000000000010'

        self.assertEqual( 512 / 8, len(padding.mBytes) )
        self.assertEqual(padded, padding.toHex())

class hash_test(unittest.TestCase):

    def hash_test(self, h, m, d):
        message = cryptobuffer()
        digest  = cryptobuffer()
        expected = cryptobuffer()
        
        print "Message: '" + m + "'"
        print "Expected Hash: ", d

        message.fromString(m)
        expected.fromHex(d)

        digest.mBytes = h.digest(message.mBytes)            
        self.assertEqual( digest.toHex(), expected.toHex() )

        
class sha1_test(hash_test):

    def setUp(self):
        self.my_digest = sha1()

    def test_sha1_lazydog(self):
        self.hash_test(self.my_digest, "The quick brown fox jumps over the lazy dog",\
                           "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")

    def test_sha1_lazycog(self):
        self.hash_test(self.my_digest, "The quick brown fox jumps over the lazy cog",\
                           "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3")

    def test_sha1_empty(self):
        self.hash_test(self.my_digest, "",\
                           "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        
    def test_sha1_mac(self):
        key = cryptobuffer()
        message = cryptobuffer()
        expected = cryptobuffer()
        digest = cryptobuffer()

        message.fromFile("data/vanilla.txt")
        key.fromString("YELLOW SUBMARINE")
        expected.fromHex("110e1e9697cd14920c7f4584d82394058daa1387")
        
        digest.mBytes = self.my_digest.keyed_mac(key.mBytes, message.mBytes)        
        self.assertEqual( digest.toHex(), expected.toHex() )      

class md4_test(hash_test):

    def setUp(self):
        self.my_digest = md4()

    def test_md4_lazydog(self):
        self.hash_test(self.my_digest, "The quick brown fox jumps over the lazy dog",\
                           "1bee69a46ba811185c194762abaeae90")

    def test_md4_lazycog(self):
        self.hash_test(self.my_digest, "The quick brown fox jumps over the lazy cog",\
                           "b86e130ce7028da59e672d56ad0113df")

    def test_md4_empty(self):
        self.hash_test(self.my_digest, "",\
                           "31d6cfe0d16ae931b73c59d7e0c089c0")

    def test_md4_a(self):
        self.hash_test(self.my_digest, "a",\
                           "bde52cb31de33e46245e05fbdbd6fb24")

    def test_md4_abc(self):
        self.hash_test(self.my_digest, "abc",\
                           "a448017aaf21d8525fc10ae87aa6729d")

    def test_md4_alphabet(self):
        self.hash_test(self.my_digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",\
                           "043f8582f241db351ce627e153e7f0e4")

    def test_md4_numbers(self):
        self.hash_test(self.my_digest, "12345678901234567890123456789012345678901234567890123456789012345678901234567890",\
                           "e33b4ddc9c38f2199c3e7b164fcc0536")
        

class hmac_test(unittest.TestCase):

    def hmac_test(self, k, m, d):
        key = cryptobuffer()
        message = cryptobuffer()
        digest  = cryptobuffer()
        expected = cryptobuffer()
    
        print
        print "HMAC"
        print "Message: '" + m + "'"
        print "Key: '" + k + "'"
        print "Expected Hash: ", d

        key.fromString(k)
        message.fromString(m)
        expected.fromHex(d)

        hmac_sha1 = fixed_key_hash(key.mBytes, sha1())

        digest.mBytes = hmac_sha1.hmac(message.mBytes)            
        self.assertEqual( digest.toHex(), expected.toHex() )

    def test_blank(self):
        self.hmac_test("","","fbdb1d1b18aa6c08324b7d64b71fb76370690e1d")
        
    def test_key(self):
        self.hmac_test("key", "The quick brown fox jumps over the lazy dog",\
                           "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")

    def test_timing_leak(self):
        web = server()
        attack = hash_break(sha1())
        message = cryptobuffer()
        required_hmac = cryptobuffer()
        message.fromString("secretfile")
        required_hmac.mBytes = web.algo.hmac(message)

        print
        print "Injected message: ", message.toString()
        print "Required HMAC:    ", required_hmac.toHex()

        hmac = attack.timing_leak_attack(web.insecure_compare, message)
        self.assertEquals( hmac, required_hmac.mBytes )

class hash_attack_test(unittest.TestCase):

    def hash_attack(self, m, k, a, algo):
        message = cryptobuffer()
        key = cryptobuffer()
        digest  = cryptobuffer()
        new_digest = cryptobuffer()

        new_message = cryptobuffer()
        ext_message = cryptobuffer()
        ext_hash = cryptobuffer()

        keyed_hash = fixed_key_hash(k, algo)
        attack = hash_break(algo)

        message.fromString(m)
        key.fromString(k)
        digest.mBytes = keyed_hash.digest(message.mBytes)

        new_message.fromString(a)
        message_and_hash = attack.extend_hash(digest.mBytes, message.mBytes, new_message.mBytes, keyed_hash.is_valid_hash)
        ext_message.mBytes = message_and_hash[0]
        ext_hash.mBytes = message_and_hash[1]

        print
        print "Attack message: ", ext_message.toPrintable()
        print "Expected Digest:  ", ext_hash.toHex()

        new_digest.mBytes = keyed_hash.digest(ext_message.mBytes)

        print "Obtained SHA1:  ", new_digest.toHex()

        self.assertEqual( new_digest.toHex(), ext_hash.toHex() )      
        
    def yellow_submarine_attack(self, algo):
        self.hash_attack("message", "YELLOW SUBMARINE", "attack", algo)

    def bacon_attack(self, algo):
        b = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
        words = []
        with open('data/vanilla.txt','r') as f:
            for line in f:
                for word in line.split():
                    words.append(word)
        k = random.choice(words)
        self.hash_attack(b, k, ";admin=true", algo)
        
    def test_yellow_submarine_sha1(self):
        self.yellow_submarine_attack(sha1())

    def test_yellow_submarine_md4(self):
        self.yellow_submarine_attack(md4())

    def test_bacon_sha1(self):
        self.bacon_attack(sha1())

    def test_bacon_md4(self):
        self.bacon_attack(md4())


if __name__ == '__main__':
    unittest.main()

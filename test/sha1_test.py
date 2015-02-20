import unittest
import random
from cryptobuffer import cryptobuffer
from sha1 import sha1, sha1_fixed_key
from sha1_attack import sha1_attack

class sha1_test(unittest.TestCase):

    def setUp(self):
        self.mySha1 = sha1()
        self.myAttack = sha1_attack()

    def test_padding(self):
        message = cryptobuffer()
        padding = cryptobuffer()

        message.fromHex('FFFF')
        padding.mBytes = self.mySha1.pre_process(message.mBytes)

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
        
    def test_sha1_lazydog(self):
        message = cryptobuffer()
        digest  = cryptobuffer()
        expected = cryptobuffer()

        message.fromString("The quick brown fox jumps over the lazy dog")
        expected.fromHex("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")

        digest.mBytes = self.mySha1.calc_sha1(message.mBytes)
            
        self.assertEqual( digest.toHex(), expected.toHex() )
 
    def test_sha1_lazycog(self):
        message = cryptobuffer()
        digest  = cryptobuffer()
        expected = cryptobuffer()

        message.fromString("The quick brown fox jumps over the lazy cog")
        expected.fromHex("de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3")
        
        digest.mBytes = self.mySha1.calc_sha1(message.mBytes)
        
        self.assertEqual( digest.toHex(), expected.toHex() )         

    def test_sha1_empty(self):
        message = cryptobuffer()
        digest  = cryptobuffer()
        expected = cryptobuffer()

        message.fromString("")
        expected.fromHex("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        
        digest.mBytes = self.mySha1.calc_sha1(message.mBytes)
        
        self.assertEqual( digest.toHex(), expected.toHex() )      

    def test_sha1_mac(self):
        message = cryptobuffer()
        key = cryptobuffer()
        digest  = cryptobuffer()
        expected = cryptobuffer()

        message.fromFile("data/vanilla.txt")
        key.fromString("YELLOW SUBMARINE")
        expected.fromHex("110e1e9697cd14920c7f4584d82394058daa1387")
        
        digest.mBytes = self.mySha1.sha1_keyed_mac(key.mBytes, message.mBytes)
        
        self.assertEqual( digest.toHex(), expected.toHex() )      

    def test_sha1_attack(self):
        message = cryptobuffer()
        key = cryptobuffer()
        digest  = cryptobuffer()
        new_digest = cryptobuffer()

        new_message = cryptobuffer()
        ext_message = cryptobuffer()
        ext_hash = cryptobuffer()

        message.fromString("message")
        key.fromString("YELLOW SUBMARINE")
        digest.mBytes = self.mySha1.sha1_keyed_mac(key.mBytes, message.mBytes)

        new_message.fromString("attack")
        # Assume that the key length is known (it was in the original attack)
        message_and_hash = self.myAttack.attack_known_length(message.mBytes, digest.mBytes, new_message.mBytes, len(key.mBytes))
        ext_message.mBytes = message_and_hash[0]
        ext_hash.mBytes = message_and_hash[1]

        print
        print "Attack message: ", ext_message.toPrintable()
        print "Expected SHA1:  ", ext_hash.toHex()

        new_digest.mBytes = self.mySha1.sha1_keyed_mac(key.mBytes, ext_message.mBytes)

        print "Obtained SHA1:  ", new_digest.toHex()

        self.assertEqual( new_digest.toHex(), ext_hash.toHex() )      
        
    def test_bacon_attack(self):
        message = cryptobuffer()
        key = cryptobuffer()
        digest  = cryptobuffer()
        new_digest = cryptobuffer()

        new_message = cryptobuffer()
        ext_message = cryptobuffer()
        ext_hash = cryptobuffer()

        message.fromString("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
        
        words = []
        with open('data/vanilla.txt','r') as f:
            for line in f:
                for word in line.split():
                    words.append(word)

        key.fromString(random.choice(words))
        sha_fixed = sha1_fixed_key(key.mBytes)
        new_message.fromString("attack")

        # Assume that the key length is known (it was in the original attack)
        message_and_hash = self.myAttack.attack_brute_length(sha_fixed.calc_sha1_fixed_key, message.mBytes, new_message.mBytes)
        ext_message.mBytes = message_and_hash[0]
        ext_hash.mBytes = message_and_hash[1]

        print
        print "Attack message: ", ext_message.toPrintable()
        print "Expected SHA1:  ", ext_hash.toHex()

        new_digest.mBytes = sha_fixed.calc_sha1_fixed_key(ext_message.mBytes)

        print "Obtained SHA1:  ", new_digest.toHex()

        self.assertEqual( new_digest.toHex(), ext_hash.toHex() )      
       

if __name__ == '__main__':
    unittest.main()

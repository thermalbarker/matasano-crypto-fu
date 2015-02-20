import unittest
from cryptobuffer import cryptobuffer
from sha1 import sha1

class sha1_test(unittest.TestCase):

    def setUp(self):
        self.mySha1 = sha1()

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


if __name__ == '__main__':
    unittest.main()

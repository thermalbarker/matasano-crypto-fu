import unittest
from xoranalysis import xor
from cryptobuffer import cryptobuffer

class xor_test(unittest.TestCase):

    def setUp(self):
        self.hexmsg = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        self.testfile = "data/4.txt"
        self.xorcracker = xor()
        self.plain1 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        self.xor1 = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        self.key = "ICE"

    def test_crackhex(self):
        print 
        results = self.xorcracker.crackhex(self.hexmsg)
        minline = min(results, key=lambda t: t[1])
        print "Most likely character: ", minline[0]
        print "With text: ", minline[2].toString()
        self.assertEqual("X", minline[0])

    def test_crackfile(self):
        results = self.xorcracker.crackfile(self.testfile)
        minline = min(results, key=lambda t: t[2])
        print "Most likely line: ", minline[0]
        print "Most likely character: ", minline[1]
        print "With text: ", minline[3].toString()
        self.assertEqual("5", minline[1])
        self.assertEqual(171, minline[0])

    def test_repeating_xor(self):
        c = cryptobuffer()
        k = cryptobuffer()
        c.fromString(self.plain1)
        k.fromString(self.key)
        result = c.xor(k)
        self.assertEqual(self.xor1, result.toHex())

if __name__ == '__main__':
    unittest.main()

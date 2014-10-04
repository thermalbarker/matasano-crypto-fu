import unittest
from xoranalysis import xor
from cryptobuffer import cryptobuffer

class xor_test(unittest.TestCase):

    def setUp(self):
        self.hexmsg = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        self.testfile = "data/4.txt"
        self.xorcracker = xor()

    def test_crackhex(self):
        print 
        results = self.xorcracker.crackhex(self.hexmsg)
        minline = min(results, key=lambda t: t[1])
        print "Most likely character: ", minline[0]
        print "With text: ", minline[2].toString()
        self.assertEqual("X", minline[0])

    def test_crackfile(self):
        print
        results = self.xorcracker.crackfile(self.testfile)
        minline = min(results, key=lambda t: t[2])
        print "Most likely line: ", minline[0]
        print "Most likely character: ", minline[1]
        print "With text: ", minline[3].toString()
        self.assertEqual("5", minline[1])
        self.assertEqual(171, minline[0])

    def test_crack_xor(self):
        print
        filename = "data/6.txt"
        buff = cryptobuffer()
        buff.fromBase64File(filename)
        results = self.xorcracker.crack_xor(buff, 1, 40)
        self.assertEqual("Terminator X: Bring the noise", results[0])
        print "The plaintext: "
        print buff.xor(results[0]).toString()

if __name__ == '__main__':
    unittest.main()

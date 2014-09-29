import unittest
from xoranalysis import xor

class xor_test(unittest.TestCase):

    def setUp(self):
        self.hexmsg = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        self.testfile = "data/4.txt"
        self.xorcracker = xor()

    def test_crackhex(self):
        results = self.xorcracker.crackhex(self.hexmsg)
        self.assertEqual("X", min(results, key=results.get))

if __name__ == '__main__':
    unittest.main()

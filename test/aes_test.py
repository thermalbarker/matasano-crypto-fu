import unittest
from aes import aes
from cryptobuffer import cryptobuffer

class aes_test(unittest.TestCase):

    def setUp(self):
        self.myAes = aes()
        self.key = cryptobuffer()
        self.ekey = cryptobuffer()
        self.skey = cryptobuffer()

    def test_keyExpansion(self):
        self.key.fromHex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
        self.skey.fromHex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" + 
                          "62 63 63 63 62 63 63 63 62 63 63 63 62 63 63 63" + 
                          "9b 98 98 c9 f9 fb fb aa 9b 98 98 c9 f9 fb fb aa" + 
                          "90 97 34 50 69 6c cf fa f2 f4 57 33 0b 0f ac 99" + 
                          "ee 06 da 7b 87 6a 15 81 75 9e 42 b2 7e 91 ee 2b" + 
                          "7f 2e 2b 88 f8 44 3e 09 8d da 7c bb f3 4b 92 90" + 
                          "ec 61 4b 85 14 25 75 8c 99 ff 09 37 6a b4 9b a7" + 
                          "21 75 17 87 35 50 62 0b ac af 6b 3c c6 1b f0 9b" + 
                          "0e f9 03 33 3b a9 61 38 97 06 0a 04 51 1d fa 9f" + 
                          "b1 d4 d8 e2 8a 7d b9 da 1d 7b b3 de 4c 66 49 41" + 
                          "b4 ef 5b cb 3e 92 e2 11 23 e9 51 cf 6f 8f 18 8e") 
        self.ekey.mBytes = self.myAes.expandKey(self.key.mBytes)
        print "Got:  ", self.ekey.toHex()
        print "Want: ", self.skey.toHex()
        self.assertEqual(self.skey.mBytes, self.ekey.mBytes)

if __name__ == '__main__':
    unittest.main()

import unittest
from aesanalysis import aesanalysis
from aes import aes, AesBlockmode
from blackbox import blackbox
from cryptobuffer import cryptobuffer

class aesanalysis_test(unittest.TestCase):

    def setUp(self):
        self.aes_cracker = aesanalysis()
        self.aes = aes()
        self.key = "YELLOW SUBMARINE"

    def test_detectaesline(self):
        print
        filename = "data/8.txt"
        results = self.aes_cracker.detectAesEcb(filename)
        for i in range(0, 10):
            r = results[i]
            print "Line: ", r[0], " ham: ", r[1], " min: ", r[2]
            print r[3].toHex()
            #print self.aes.decryptECB(r[3].mBytes, self.key)

    def test_detectaesline(self):
        print
        tries = 100
        correct = 0
        for i in range(0, tries):
            box = blackbox()
            mode = self.aes_cracker.detectAesEcbFunc(box.blackBoxFunction)
            if ((box.algo is AesBlockmode.ECB) == mode):
                correct += 1
        self.assertEqual(tries, correct)


    def test_decryptaesecb(self):
        print
        # Set up the black box with a plain text
        box = blackbox()
        text = cryptobuffer()
        text.fromBase64File("data/12.txt")
        box.aesEcbUnknown = text.mBytes
        print "Decrypting AES-ECB with chosen boundary attack:"
        decrypted = self.aes_cracker.decryptAesEcbFunc(box.blackBoxFunction2)
        self.assertEqual(text.mBytes, decrypted)

if __name__ == '__main__':
    unittest.main()

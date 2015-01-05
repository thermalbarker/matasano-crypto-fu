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
            #print "Line: ", r[0], " ham: ", r[1], " min: ", r[2]
            #print r[3].toHex()
            #print self.aes.decryptECB(r[3].mBytes, self.key)

    def test_detectaes(self):
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
        # Change the below to 12.txt, but it takes ages!
        text.fromBase64File("data/12a.txt")
        box.aesEcbUnknown = text.mBytes
        print "Decrypting AES-ECB with chosen boundary attack:"
        decrypted = self.aes_cracker.decryptAesEcbFunc(box.blackBoxFunction2)
        self.assertEqual(text.mBytes, decrypted)

    def test_decryptctr(self):
        print
        box = blackbox()
        plainAndCypherTexts = box.encryptCtrLinesFromFile("data/20.txt")
        self.aes_cracker.decryptCtrFixedNonce(plainAndCypherTexts[1])

    def test_breakRandomAccessCtr(self):
        box = blackbox()
        key = cryptobuffer()
        cypher = cryptobuffer()
        ctr = cryptobuffer()
        crackedText = cryptobuffer()
        plain = cryptobuffer()

        filename = "data/25a.txt"
        key.fromString("YELLOW SUBMARINE")
        cypher.fromBase64File(filename)
        plain.mBytes = self.aes.decryptECB(cypher.mBytes, key.mBytes)
        ctr.mBytes = box.encryptWithCtr(plain.mBytes)

        # Just check the CTR function is working OK:
        self.assertEqual(plain.mBytes, box.encryptWithCtr(ctr.mBytes))

        print plain.toString()       

        crackedText.mBytes = self.aes_cracker.breakRandomAccessCtr(ctr.mBytes, box.editCtr)
        self.assertEqual(crackedText.mBytes, plain.mBytes)

if __name__ == '__main__':
    unittest.main()

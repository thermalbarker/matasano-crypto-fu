import unittest
from aes import aes
from cryptobuffer import cryptobuffer

class aes_test(unittest.TestCase):

    def setUp(self):
        self.myAes = aes()
        self.key = cryptobuffer()
        self.ekey = cryptobuffer()
        self.skey = cryptobuffer()
        self.buff = cryptobuffer()
        self.cypher = cryptobuffer()

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
        print
        #print "Got:  ", self.ekey.toHex()
        #print "Want: ", self.skey.toHex()
        self.assertEqual(self.skey.mBytes, self.ekey.mBytes)

    def test_mixColumns(self):
        self.buff.fromHex("db 13 53 45")
        self.cypher.fromHex("8e 4d a1 bc")
        self.buff.mBytes = self.myAes.mixColumn(self.buff.mBytes)
        self.assertEqual(self.cypher.toHex(), self.buff.toHex())

    def test_shiftRows(self):
        self.buff.fromHex("00 01 02 03"+
                          "10 11 12 13"+
                          "20 21 22 23"+
                          "30 31 32 33")
        self.cypher.fromHex("00 01 02 03"+
                            "11 12 13 10"+
                            "22 23 20 21"+
                            "33 30 31 32")
        self.buff.mBytes = self.myAes.shiftRows(self.buff.mBytes)
        self.assertEqual(self.cypher.toHex(), self.buff.toHex())

    def test_singleBlock(self):
        print
        self.key.fromHex("2b7e151628aed2a6abf7158809cf4f3c")
        self.buff.fromHex("32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34")
        self.cypher.fromHex("3925841d02dc09fbdc118597196a0b32")
        self.buff.mBytes = self.myAes.encryptBlock(self.buff.mBytes, self.key.mBytes)
        self.assertEqual(self.cypher.toHex(), self.buff.toHex())


    def test_singleBlockZeroKey(self):
        print
        self.key.fromHex("00000000000000000000000000000000")
        self.buff.fromHex("80000000000000000000000000000000")
        self.cypher.fromHex("3ad78e726c1ec02b7ebfe92b23d9ec34")
        self.buff.mBytes = self.myAes.encryptBlock(self.buff.mBytes, self.key.mBytes)
        self.assertEqual(self.cypher.toHex(), self.buff.toHex())

    def test_ecbDecrypt(self):
        print
        print "ECB Decryption"
        cypher2 = cryptobuffer()
        filename = "data/7.txt"
        self.key.fromString("YELLOW SUBMARINE")
        print "Key:  ", self.key.toHex()
        self.cypher.fromBase64File(filename)
        self.buff.mBytes = self.myAes.decryptECB(self.cypher.mBytes, self.key.mBytes)
        print self.buff.toString()
        cypher2.mBytes = self.myAes.encryptECB(self.buff.mBytes, self.key.mBytes)
        self.assertEqual(self.cypher.toHex(), cypher2.toHex())

    def test_cbcDecrypt(self):
        print
        print "CBC Decryption"
        cypher2 = cryptobuffer()
        iv = cryptobuffer()
        filename = "data/10.txt"
        self.key.fromString("YELLOW SUBMARINE")
        iv.fromHex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
        print "Key:  ", self.key.toHex()
        self.cypher.fromBase64File(filename)
        self.buff.mBytes = self.myAes.decryptCBC(self.cypher.mBytes, self.key.mBytes, iv.mBytes)
        print self.buff.toString()
        cypher2.mBytes = self.myAes.encryptCBC(self.buff.mBytes, self.key.mBytes, iv.mBytes)
        self.assertEqual(self.cypher.toHex(), cypher2.toHex())

    def test_ctrDecrypt(self):
        print
        print "CTR Decryption"
        cypher2 = cryptobuffer()
        nonce  = cryptobuffer()
        filename = "data/18.txt"
        self.key.fromString("YELLOW SUBMARINE")
        nonce.fromHex("00 00 00 00 00 00 00 00")
        print "Key:  ", self.key.toHex()
        self.cypher.fromBase64File(filename)
        self.buff.mBytes = self.myAes.decryptCTR(self.cypher.mBytes, self.key.mBytes, nonce.mBytes)
        print self.buff.toString()
        cypher2.mBytes = self.myAes.encryptCTR(self.buff.mBytes, self.key.mBytes, nonce.mBytes)
        self.assertEqual(self.cypher.toHex(), cypher2.toHex())
        
    def test_ctrReEncrypt(self):
        print
        print "CTR Re-encryption"
        cypher2 = cryptobuffer()
        plain = cryptobuffer()
        nonce  = cryptobuffer()
        edit = cryptobuffer()
        filename = "data/18.txt"
        self.key.fromString("YELLOW SUBMARINE")
        edit.fromString("OCRE SUBMERSIBLE")
        nonce.fromHex("00 00 00 00 00 00 00 00")
        print "Key:  ", self.key.toHex()
        self.cypher.fromBase64File(filename)
        print len(self.key.mBytes)

        for i in range(0, len(self.cypher.mBytes)):
            for j in range(1, len(edit.mBytes)):
                cypher2.mBytes = self.myAes.reencryptCTR(self.cypher.mBytes, self.key.mBytes, \
                                                             nonce.mBytes, i, edit.mBytes[0:j])
                plain.mBytes = self.myAes.decryptCTR(cypher2.mBytes, self.key.mBytes, nonce.mBytes)
                #print plain.toString()
                self.assertEqual( edit.mBytes[0:j], plain.mBytes[i:i+j] )


if __name__ == '__main__':
    unittest.main()

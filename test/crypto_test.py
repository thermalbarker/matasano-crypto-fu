import unittest
from cryptobuffer import cryptobuffer

class cryptobuffer_test(unittest.TestCase):

    def setUp(self):
        self.hexmsg = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        self.base64msg = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        self.textmsg = "I'm killing your brain like a poisonous mushroom"
        self.buff = cryptobuffer()
        self.buff.fromHex(self.hexmsg)
 
    def test_hex_to_base64(self):
        self.assertEqual(self.base64msg, self.buff.toBase64())

    def test_hex_to_hex(self):
        self.assertEqual(self.hexmsg, self.buff.toHex())

    def test_hex_to_text(self):
        self.assertEqual(self.textmsg, self.buff.toString())

    def test_base64_to_base64(self):
        self.buff.fromBase64(self.base64msg)
        self.assertEqual(self.base64msg, self.buff.toBase64())

    def test_text_to_base64(self):
        self.buff.fromString(self.textmsg)
        self.assertEqual(self.base64msg, self.buff.toBase64())

    def fixed_xor(self):
        self.buff.fromHex("1c0111001f010100061a024b53535009181c")
        xortarget = cryptobuffer()
        xortarget.fromHex("686974207468652062756c6c277320657965")
        self.buff.xor(xortarget)
        self.assertEqual("746865206b696420646f6e277420706c6179", self.buff.toHex())
    

if __name__ == '__main__':
    unittest.main()

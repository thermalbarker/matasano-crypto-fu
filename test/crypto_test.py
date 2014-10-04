import unittest
from cryptobuffer import cryptobuffer

class cryptobuffer_test(unittest.TestCase):

    def setUp(self):
        self.hexmsg = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        self.base64msg = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        self.textmsg = "I'm killing your brain like a poisonous mushroom"
        self.buff = cryptobuffer()
        self.buff.fromHex(self.hexmsg)
        self.plain1 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        self.xor1 = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        self.key = "ICE"
 
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

    def test_fixed_xor(self):
        self.buff.fromHex("1c0111001f010100061a024b53535009181c")
        xortarget = cryptobuffer()
        xortarget.fromHex("686974207468652062756c6c277320657965")
        result = self.buff.xor(xortarget)
        self.assertEqual("746865206b696420646f6e277420706c6179", result.toHex())

    def test_repeating_xor(self):
        c = cryptobuffer()
        k = cryptobuffer()
        c.fromString(self.plain1)
        k.fromString(self.key)
        result = c.xor(k)
        self.assertEqual(self.xor1, result.toHex())

    def test_hamming_distance(self):
        b1 = cryptobuffer()
        b1.fromString("this is a test")
        b2 = cryptobuffer()
        b2.fromString("wokka wokka!!!")
        self.assertEqual(37, b1.hamming(b2))
        
    

if __name__ == '__main__':
    unittest.main()

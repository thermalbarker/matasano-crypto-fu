import unittest
from webprofiler import webprofiler
from webprofile_analysis import webprofile_analysis
from cryptobuffer import cryptobuffer

class webprofiler_test(unittest.TestCase):

    def setUp(self):
        self.web = webprofiler()
        self.cracker = webprofile_analysis()

    def test_stringParsing(self):
        s = "foo=bar&baz=qux&zap=zazzle"
        o = self.web.parseWebString(s)
        self.assertEqual('bar', o['foo'])
        self.assertEqual('qux', o['baz'])
        self.assertEqual('zazzle', o['zap'])

        s2 = self.web.makeWebString(o)
        self.assertEqual(s, s2)

    def test_profilefor(self):
        s = self.web.profile_for_clear("foo@bar.com")
        self.assertEqual('email=foo@bar.com&uid=10&role=user', s)

    def test_illegalchars(self):
        s = self.web.profile_for_clear("foo@bar.com&role=admin")
        o = self.web.parseWebString(s)
        self.assertEquals('user', o['role'])

    def test_encryptDecrypt(self):
        s = self.web.profile_for("foo@bar.com")
        c = self.web.extract_profile(s)
        self.assertEqual('foo@bar.com', c['email'])
        self.assertEqual('10',   c['uid'])
        self.assertEqual('user',  c['role'])        
 
    def test_cut_and_paste(self):
        s = self.cracker.cut_and_paste(self.web.profile_for)
        c = self.web.extract_profile(s)
        self.assertEqual('admin',  c['role'])

    def test_cbc_bitflip_attack(self):
        # Use CTR encryption
        self.web.setCBC()
        s = self.cracker.cbc_bitflip(self.web.cooking_user_bacon,
                                     self.web.search_for_admin)
        self.assertTrue(s)

    def test_ctr_bitflip_attack(self):
        # Use CTR encryption
        self.web.setCTR()
        s = self.cracker.ctr_bitflip(self.web.cooking_user_bacon,
                                     self.web.search_for_admin)
        self.assertTrue(s)

    def notest_cbc_padding_oracle(self):
        plain = cryptobuffer()
        plain.fromRandomLineInBase64File("data/17.txt")
        iv_and_secret = self.web.random_secret(plain.toString())
        
        result = cryptobuffer()
        result.mBytes = self.cracker.cbc_padding_attack(
            iv_and_secret[0], iv_and_secret[1],
            self.web.cbc_padding_oracle)

        print "The secret string is: "
        print plain.toString()

        self.assertEquals(plain.toString(), result.toString())


if __name__ == '__main__':
    unittest.main()

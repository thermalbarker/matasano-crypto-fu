import unittest
from webprofiler import webprofiler
from webprofile_analysis import webprofile_analysis

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
 
    def test_analysis(self):
        s = self.cracker.cut_and_paste(self.web.profile_for)
        c = self.web.extract_profile(s)
        self.assertEqual('admin',  c['role'])

if __name__ == '__main__':
    unittest.main()

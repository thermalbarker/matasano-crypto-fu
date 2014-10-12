import unittest
from webprofiler import webprofiler

class webprofiler_test(unittest.TestCase):

    def setUp(self):
        self.web = webprofiler()

    def test_stringParsing(self):
        s = "foo=bar&baz=qux&zap=zazzle"
        o = self.web.parseWebString(s)
        self.assertEqual('bar', o['foo'])
        self.assertEqual('qux', o['baz'])
        self.assertEqual('zazzle', o['zap'])

        s2 = self.web.makeWebString(o)
        self.assertEqual(s, s2)

    def test_profilefor(self):
        s = self.web.profile_for("foo@bar.com")
        self.assertEqual('email=foo@bar.com&uid=10&role=user', s)

    def test_illegalchars(self):
        s = self.web.profile_for("foo@bar.com&role=admin")
        o = self.web.parseWebString(s)
        self.assertEquals('user', o['role'])

if __name__ == '__main__':
    unittest.main()

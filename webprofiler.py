from blackbox import blackbox
from collections import OrderedDict

class webprofiler(blackbox):

    def __init__(self):
        self.uid = 10

    def parseWebString(self, string):
        result = OrderedDict()
        # e.g. foo=bar&baz=qux&zap=zazzle
        for keyvalue in string.split('&'):
            key = keyvalue.split('=')[0]
            value = keyvalue.split('=')[1]
            result[key] = value
        return result

    def makeWebString(self, dic):
        result = ""
        first = True
        for key in dic:
            if not first:
                result += "&"
            first = False
           # eat = and &
            keyforstring = key.translate(None, '=&')
            valueforstring = dic[key].translate(None, '=&')
            result += keyforstring + "=" + valueforstring
        return result

    def profile_for(self, email):
        d = OrderedDict()
        d['email'] = str(email)
        d['uid'] = str(self.uid)
        d['role'] = 'user'
        return self.makeWebString(d)

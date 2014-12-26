import math, string

class frequency(object):

    unknown = 'other'

    def __init__(self):
        self.freq = dict()
        for c in string.printable:
            self.freq[c] = 0
        self.freq[self.unknown] = 0

    def __str__(self):
        s = str()
        for c in self.freq:
            s += c + ': ' + str(self.freq[c]) + '\n'
        return s

    def addText(self, text):
        # Remove multiple spaces
        text.strip()
        " ".join(text.split())
        for c in text.lower():
            if c in self.freq:
                self.freq[c] += 1
            elif self.unknown in self.freq:
                self.freq[self.unknown] += 1
            else:
                self.freq[self.unknown] = 1
        self.normalise()

    def normalise(self):
        factor = 100.0/sum(self.freq.itervalues())
        for k in self.freq:
            self.freq[k] = self.freq[k] * factor

    def compare(self, other):
        chisq = 0
        for k in self.freq:
            if k in other.freq:
                o = other.freq[k]
            else:
                o = 0
            diff = self.freq[k] - o
            chisq = chisq + diff * diff
        chisq = math.sqrt(chisq) / len(self.freq)
        return chisq

class englishfrequency(frequency):

    def __init__(self):
        super(frequency,self).__init__()
        self.freq = {
            'a' : 8.167,
            'b' : 1.492,
            'c' : 2.782,
            'd' : 4.253,
            'e' : 12.702,
            'f' : 2.228,
            'g' : 2.015,
            'h' : 6.094,
            'i' : 6.966,
            'j' : 0.153,
            'k' : 0.772,
            'l' : 4.025,
            'm' : 2.406,
            'n' : 6.749,
            'o' : 7.507,
            'p' : 1.929,
            'q' : 0.095,
            'r' : 5.987,
            's' : 6.327,
            't' : 9.056,
            'u' : 2.758,
            'v' : 0.978,
            'w' : 2.360,
            'x' : 0.150,
            'y' : 1.974,
            'z' : 0.074,
            ' ': 20.8768,
            self.unknown : 0
            }
        self.normalise()

# Use an input file to train the frequency
class filefrequency(frequency):

    def __init__(self, filename):
        super(frequency, self).__init__()
        self.freq = dict()
        infile = open(filename, "r")
        for line in infile:
            for c in line:
                if c not in self.freq:
                    self.freq[c] = 0
                self.freq[c] += 1
        self.normalise()
        infile.close()

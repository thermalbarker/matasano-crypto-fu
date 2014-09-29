import math

class frequency(object):

    def __init__(self):
        self.freq = {
            'a' : 0,
            'b' : 0,
            'c' : 0,
            'd' : 0,
            'e' : 0,
            'f' : 0,
            'g' : 0,
            'h' : 0,
            'i' : 0,
            'j' : 0,
            'k' : 0,
            'l' : 0,
            'm' : 0,
            'n' : 0,
            'o' : 0,
            'p' : 0,
            'q' : 0,
            'r' : 0,
            's' : 0,
            't' : 0,
            'u' : 0,
            'v' : 0,
            'w' : 0,
            'x' : 0,
            'y' : 0,
            'z' : 0,
            ' ' : 0,
            'other': 0
            }

    def addText(self, text):
        # Remove multiple spaces
        text.strip()
        " ".join(text.split())
        for c in text.lower():
            if c in self.freq:
                self.freq[c] += 1
            else:
                self.freq['other'] += 1
        self.normalise()

    def normalise(self):
        factor = 100.0/sum(self.freq.itervalues())
        for k in self.freq:
            self.freq[k] = self.freq[k] * factor

    def compare(self, other):
        chisq = 0
        for k in self.freq:
            diff = self.freq[k] - other.freq[k]
            chisq = chisq + diff * diff
        chisq = math.sqrt(chisq) / len(self.freq)
        return chisq

    def engchisq(self):
        english = englishfrequency()
        return self.compare(english)
    

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
            'other' : 0
            }
        self.normalise()

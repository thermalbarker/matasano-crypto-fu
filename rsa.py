from random import randrange

from cryptobuffer import cryptobuffer

# A = (g ** a) % p
# Nice explanation here:
# https://en.wikipedia.org/wiki/Modular_exponentiation
def modexp(g, a, p):
    if (p == 1):
        return 0
    c = 1
    g = g % p
    while a > 0:
        if ((a % 2) == 1):
            c = (c * g) % p
        a = a >> 1
        g = (g ** 2) % p
    return c

small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31] # etc.

# Stolen from http://stackoverflow.com/questions/14613304/rabin-miller-strong-pseudoprime-test-implementation-wont-work
# The challenge suggests skipping this anyway...
def probably_prime(n, k = 41):
    """Return True if n passes k rounds of the Miller-Rabin primality
    test (and is probably prime). Return False if n is proved to be
    composite.

    """
    if n < 2: return False
    for p in small_primes:
        if n < p * p: return True
        if n % p == 0: return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits = 1024, rounds = 41):
    while True:
        n = randrange(2, 2 ** bits)
        if probably_prime(n, rounds):
            return n

# This one comes from stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def xgcd(b, n):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while n != 0:
        q, b, n = b // n, n, b % n
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return  b, x0, y0

#https://rosettacode.org/wiki/Modular_inverse#Python
def rgcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

def modinv(a, m):
    g, x, y = rgcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

# http://stackoverflow.com/questions/356090/how-to-compute-the-nth-root-of-a-very-big-integer
def invpow(x,n):
    """Finds the integer component of the n'th root of x,
    an integer such that y ** n <= x < (y + 1) ** n.
    """
    high = 1
    while high ** n <= x:
        high *= 2
    low = high/2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1

def gen_key_pair(e):
    d = None

    while d is None:
        p = gen_prime()
        q = gen_prime()

        n = p * q
        et = (p - 1) * (q - 1)

        try:
            # Sometimes this does not work, not sure why
            d = modinv(e, et)
        except:
            d = None

    return d, n

def encrypt(m, e, n):
    return modexp(m, e, n)

def decrypt(c, d, n):
    return modexp(c, d, n)

def encrypt_str(b, e, n):
    buff = cryptobuffer()
    buff.mBytes = b
    m = buff.toInt()
    c = encrypt(m, e, n)
    buff.fromInt(c)
    return buff.mBytes

def decrypt_str(b, d, n):
    buff = cryptobuffer()
    buff.mBytes = b
    c = buff.toInt()
    m = decrypt(c, d, n)
    buff.fromInt(m)
    return buff.mBytes




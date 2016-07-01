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

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def gen_key_pair(e = 3):
    p = gen_prime()
    q = gen_prime()

    n = p * q
    et = (p - 1) * (q - 1)
    d = modinv(e, et)

    return d, n






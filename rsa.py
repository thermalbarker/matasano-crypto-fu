from random import randrange
import cryptomath 
from cryptobuffer import cryptobuffer

def gen_key_pair(e):
    d = None

    while d is None:
        p = cryptomath.gen_prime()
        q = cryptomath.gen_prime()

        n = p * q
        et = (p - 1) * (q - 1)

        try:
            # Sometimes this does not work, not sure why
            d = cryptomath.modinv(e, et)
        except:
            d = None

    return d, n

def encrypt(m, e, n):
    return cryptomath.modexp(m, e, n)

def decrypt(c, d, n):
    return cryptomath.modexp(c, d, n)

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




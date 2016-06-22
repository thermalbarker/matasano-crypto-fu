from aes import aes
from hash import sha1
from cryptobuffer import cryptobuffer

# A = (g ** a) % p
# Nice explanation here:
# https://en.wikipedia.org/wiki/Modular_exponentiation
def tom_modexp(g, a, p):
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

def dh_public_key(p, g, private_key):
    return tom_modexp(g, private_key, p)

def dh_shared_secret(p, pub_theirs, priv_ours):
    return tom_modexp(pub_theirs, priv_ours, p)

def dh_encrypt(msg, s, iv):
    mAES = aes()
    mSHA1 = sha1()
    s_buff = cryptobuffer()
    s_buff.fromInt(s)
    aes_key = mSHA1.digest(s_buff.mBytes)[0:16]
    return mAES.encryptCBC(msg, aes_key, iv)

def dh_decrypt(msg, s, iv):
    mAES = aes()
    mSHA1 = sha1()
    s_buff = cryptobuffer()
    s_buff.fromInt(s)
    aes_key = mSHA1.digest(s_buff.mBytes)[0:16]
    return mAES.decryptCBC(msg, aes_key, iv)



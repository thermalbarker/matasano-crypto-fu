from aes import aes
from hash import sha1
from cryptobuffer import cryptobuffer
from cryptomath import modexp

def dh_public_key(p, g, private_key):
    return modexp(g, private_key, p)

def dh_shared_secret(p, pub_theirs, priv_ours):
    return modexp(pub_theirs, priv_ours, p)

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



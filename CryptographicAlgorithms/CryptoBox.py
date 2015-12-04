﻿import random, utils, RSA, ElGamal, DSA

from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.Cipher import AES, DES3
from Crypto import Random
from Crypto.Util import Counter

from binascii import unhexlify, hexlify

def generateHash(str, sec_level = 1):
    hasher = None
    if sec_level == 1:
        hasher = SHA256.new()

    elif sec_level == 2:
        hasher = SHA384.new()

    elif sec_level == 3:
        hasher = SHA512.new()

    hasher.update(str)
    hash = hasher.digest()

    return hash


def AESencryption(message, sec_level = 1):
    key = None
    if sec_level == 1:
        key = utils.generateKey(128)

    elif sec_level == 2:
        key = utils.generateKey(192)

    elif sec_level == 3:
        key = utils.generateKey(256)

    else:
        print "No such security level"
        return -1

    iv = Random.new().read(AES.block_size)
    
    aes = AES.new(key, AES.MODE_CBC, iv)

    cipher_text = aes.encrypt(message)

    return key, cipher_text, iv


def AESdecryption(key, cipher_text, iv):
    aes = AES.new(key, AES.MODE_CBC, iv)

    message = aes.decrypt(cipher_text)

    return message


def DES3encryption(message):
    key = generateKey(16*8)
    iv = generateKey(8*8)

    des3 = DES3.new(key, DES3.MODE_CBC, iv)

    cipher_text = des3.encrypt(message)

    return key, cipher_text, iv


def DES3decryption(key, cipher_text, iv):
    des3 = DES3.new(key, DES3.MODE_CBC, iv)

    message = des3.decrypt(cipher_text)

    return message


def RSAencryption(message, security_level = 1):
    keys = RSA.generateKeys(security_level)
    e, N, d, p, q = keys[0], keys[1], keys[2], keys[3], keys[4]
    # d = private key   e = public key
    cipher_text = RSA.encrypt(N, e, message, security_level, "")

    return e, N, d, p, q, cipher_text


def RSAdecryption(N, d, p, q, cipher_text):
   
    return RSA.decrypt(N, d, p, q, cipher_text, "")


def RSAGenerateSignature(message, security_level = 1):
    keys = RSA.generateKeys(security_level)
    e, N, d, p, q = keys[0], keys[1], keys[2], keys[3], keys[4]
    # d = private key   e = public key
    signature = RSA.generateSignature(N, d, message)

    return e, N, d, p, q, signature


def RSAVerifySignature(N, e, message, signature):

    return RSA.verifySignature(N, e, message, signature)


def ElGamalEncryption(message, security_level):
    keys = ElGamal.generateKeys(security_level)
    p, q, g, x, y = keys[0], keys[1], keys[2], keys[3], keys[4]
    # x = private key   y = public key
    cipher = ElGamal.encrypt(p, q, g, y, message)
    r, t = cipher[0], cipher[1]

    return p, q, g, x, y, r, t


def ElGamalDecryption(p, q, x, r, t):

    return ElGamal.decrypt(p, q, x, r, t)


def DSAGenerateSignature(message, security_level):
    # ElGamal and DSA uses the same key generation algorithm
    keys = ElGamal.generateKeys(security_level)
    p, q, g, x, y = keys[0], keys[1], keys[2], keys[3], keys[4]
    # x = private key   y = public key
    sign = DSA.generateSignature(p, q, g, x, message)
    r, s = sign[0], sign[1]

    return p, q, g, x, y, r, s
    

def DSAVerifySignature(p, q, g, y, r, s, message):

    return DSA.verifySignature(p, q, g, y, r, s, message)
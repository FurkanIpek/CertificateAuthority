## NOTE if your inputs are in hexadecimal format,
## unhexlify them before using them as input for any of
## the following functions

import random, utils, RSA, ElGamal, DSA

from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.Cipher import AES, DES3
from Crypto import Random
from Crypto.Util import Counter

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
    # pad message with 0 to get multiples of 16 in length
    lPS = 16 - (len(message) % 16)
    message = message + '\0' * lPS
    
    cipher_text = aes.encrypt(message)

    return key, cipher_text, iv


def AESdecryption(key, cipher_text, iv):
    aes = AES.new(key, AES.MODE_CBC, iv)

    message = aes.decrypt(cipher_text)

    return message


def DES3encryption(message):
    key = utils.generateKey(16*8)
    iv = utils.generateKey(8*8)

    des3 = DES3.new(key, DES3.MODE_CBC, iv)
    # pad message with 0 to get multiples of 8 in length
    lPS = 8 - (len(message) % 8)
    message = message + '\0' * lPS
    cipher_text = des3.encrypt(message)

    return key, cipher_text, iv


def DES3decryption(key, cipher_text, iv):
    des3 = DES3.new(key, DES3.MODE_CBC, iv)

    message = des3.decrypt(cipher_text)

    return message


def RSAKeyGeneration(security_level):
    keys = RSA.generateKeys(security_level)
    e, N, d, p, q = keys[0], keys[1], keys[2], keys[3], keys[4]

    return e, N, d, p, q


def RSAencryption(N, e, message, L):
    
    return RSA.encrypt(N, e, message, L)


def RSAdecryption(N, d, p, q, cipher_text, L):
   
    return RSA.decrypt(N, d, p, q, cipher_text, L)


def RSAGenerateSignature(N, d, message):

    return RSA.generateSignature(N, d, message)


def RSAVerifySignature(N, e, message, signature):

    return RSA.verifySignature(N, e, message, signature)


def ElGamalAndDSAKeyGeneration(security_level):
    keys = ElGamal.generateKeys(security_level)
    p, q, g, x, y = keys[0], keys[1], keys[2], keys[3], keys[4]
    # x = private key   y = public key
    return p, q, g, x, y


def ElGamalEncryption(p, q, g, y, message):
    cipher = ElGamal.encrypt(p, q, g, y, message)
    r, t = cipher[0], cipher[1]

    return r, t


def ElGamalDecryption(p, q, x, r, t):

    return ElGamal.decrypt(p, q, x, r, t)


def DSAGenerateSignature(p, q, g, x, message):
    sign = DSA.generateSignature(p, q, g, x, message)
    r, s = sign[0], sign[1]

    return r, s
    

def DSAVerifySignature(p, q, g, y, r, s, message):

    return DSA.verifySignature(p, q, g, y, r, s, message)
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
    
    aes = AES.new(key, AES.MODE_CFB, iv)

    cipher_text = aes.encrypt(message)

    return key, cipher_text, iv


def AESdecryption(key, cipher_text, iv):
    aes = AES.new(key, AES.MODE_CFB, iv)

    message = aes.decrypt(cipher_text)

    return message


def DES3encryption(message):
    key = generateKey(16*8)
    iv = generateKey(8*8)

    des3 = DES3.new(key, DES3.MODE_CFB, iv)

    cipher_text = des3.encrypt(message)

    return key, cipher_text, iv


def DES3decryption(key, cipher_text, iv):
    des3 = DES3.new(key, DES3.MODE_CFB, iv)

    message = des3.decrypt(cipher_text)

    return message


def RSAencryption(message, security_level = 1):
    keys = RSA.generateKeys(1)
    e, N, d, p, q = keys[0], keys[1], keys[2], keys[3], keys[4]

    cipher_text = RSA.encrypt(N, e, message, security_level, "")

    return keys, cipher_text


def RSAdecryption(N, d, p, q, cipher_text):
    message = RSA.decrypt(N, d, p, q, cipher_text, "")

    return message


def RSAGenerateSignature(): # TODO
    return RSA.generateSignature()


def RSAVerifySignature(signature): # TODO
    return RSA.verifySignature()


def ElGamalEncryption(message): # TODO
    return ElGamal.encrypt(message)


def ElGamalDecryption(cipher_text): # TODO
    return ElGamal.decrypt(cipher_text)


def DSAGenerateSignature(): # TODO
    return DSA.generateSignature()
    

def DSAVerifySignature(signature): # TODO
    return DSA.verifySignature(signature)
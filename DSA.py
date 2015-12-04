import utils, CryptoBox

from binascii import hexlify
from Crypto.Util import number

from Crypto.Hash import _SHA256

def generateSignature(p, q, g, s, message):
    H = int(hexlify(CryptoBox.generateHash(message, 1)), 16)
    k = number.getRandomRange(1, q)
    a = utils.mod_exp(utils.mod_exp(g, k, p), 1, q)
    i = utils.inverse(k, q)
    b = utils.mod_exp(i * (H + s * a), 1, q)
    
    return a, b

def verifySignature(p, q, g, h, a, b, message):
    H = int(hexlify(CryptoBox.generateHash(message, 1)), 16)
    i = utils.inverse(b, q)
    u1 = utils.mod_exp(H * i, 1, q)
    u2 = utils.mod_exp(a * i, 1, q)
    v = utils.mod_exp(utils.mod_exp(utils.mod_exp(g, u1, p)*utils.mod_exp(h, u2, p), 1, p), 1, q)

    return True if v == a else False
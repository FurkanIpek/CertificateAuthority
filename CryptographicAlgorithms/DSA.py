import utils, CryptoBox

from binascii import hexlify
from Crypto.Util import number

def generateSignature(p, q, g, x, message):
    H = int(hexlify(CryptoBox.generateHash(message, 1)), 16)
    k = number.getRandomRange(1, q)
    r = utils.mod_exp(g, k, p) % q
    k_inv = utils.inverse(k, q)
    s = (k_inv * (H + x * r)) % q

    if (r == 0 or s == 0):
        # since it is very unlikely to make a recursive call, function will terminate eventually
        return generateSignature(p, q, g, x, message)
    
    return r, s

def verifySignature(p, q, g, y, r, s, message):
    if r <= 0 or r >= q or s <= 0 or s >= q:
        print "Rejected!"
        return

    H = int(hexlify(CryptoBox.generateHash(message, 1)), 16)
    w = utils.inverse(s, q)
    u1 = (H * w) % q
    u2 = (r * w) % q
    v = ((utils.mod_exp(g, u1, p) * utils.mod_exp(y, u2, p)) % p) % q

    return True if v == r else False
import utils

from Crypto.Util import number

def generateKeys(security_level = 1):
    prime_size, random_size = 0, 0

    if security_level == 1: prime_size, random_size = 160, 864

    elif security_level == 2: prime_size, random_size = 224, 1824

    elif security_level == 3: prime_size, random_size = 256, 2816

    else: return

    q = number.getPrime(prime_size)
    k = number.getRandomInteger(random_size)
    p = k * q + 1

    while utils.rm_primality(p) != True:
        k = utils.gen_random(random_size)
        p = k * q + 1

    a = number.getRandomRange(0, p)
    g = utils.mod_exp(a, (p - 1) / q, p)

    while g == 1:
        a = number.getRandomRange(0, p)
        g = utils.mod_exp(a, (p - 1) / q, p)

    s = number.getRandomRange(1, q - 2)
    h = utils.mod_exp(g, s, p)

    return p, q, g, s, h


def encrypt(p, q, g, h, message):
    k = number.getRandomRange(1, p - 2)
    r = utils.mod_exp(g, k, p)
    t = utils.mod_exp(utils.mod_exp(h, k, p) * message, 1, p)

    return r, t


def decrypt(p, q, s, r, t):
    k = utils.inverse(utils.mod_exp(r, s, p), p)
    message = utils.mod_exp(t * k, 1, p)

    return message
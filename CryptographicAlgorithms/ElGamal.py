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

    x = number.getRandomRange(1, q - 2)
    y = utils.mod_exp(g, x, p)

    return p, q, g, x, y


def encrypt(p, q, g, y, message):
    k = number.getRandomRange(1, p - 2)
    r = utils.mod_exp(g, k, p)
    t = (utils.mod_exp(y, k, p) * message) % p

    return r, t


def decrypt(p, q, x, r, t):
    k = utils.inverse(utils.mod_exp(r, x, p), p)
    message = (t * k) % p

    return message
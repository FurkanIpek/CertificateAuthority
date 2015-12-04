import utils, CryptoBox

from binascii import b2a_hex, hexlify, unhexlify
from os import urandom
from random import randint
from fractions import gcd

from Crypto.Util import number
from Crypto.Hash import SHA

def generateKeys(security_level = 1):
    bit_count = None

    if security_level == 1:
        bit_count = 1024 / 2
    elif security_level == 2:
        bit_count = 2048 / 2
    elif security_level == 3:
        bit_count = 3072 / 2

    p, q = number.getPrime(bit_count), number.getPrime(bit_count)

    #p = utils.gen_random(bit_count)
    #count = 3 # test primality thrice

    #while utils.rm_primality(p) == False or (utils.rm_primality(p) == True and count != 0):
    #    p = utils.gen_random(bit_count)

    #    if utils.rm_primality(p) == True:
    #        count -= 1

    #q = utils.gen_random(bit_count)
    #count = 3 # test primality thrice

    #while utils.rm_primality(q) == False or (utils.rm_primality(q) == True and count != 0):
    #    q = utils.gen_random(bit_count)

    #    if utils.rm_primality(q) == True:
    #        count -= 1

    N = p * q

    phi_N = (p-1) * (q-1)

    e = randint(1, phi_N - 1)

    while gcd(e, phi_N) != 1:
        e = randint(1, phi_N - 1)

    d = utils.inverse(e, phi_N)

    return e, N, d, p, q

def OS2IP(str):
    value = hexlify(str)

    return int(value, 16)

def RSAEP(N, e, m):
    if m < 0 or m > N - 1:
        print "Message representative out of range!"
        return -1

    return utils.mod_exp(m, e, N)

def I2OSP(x, xLen):
    if x >= pow(256, xLen):
        print "Integer too large"
        return ''

    h = hex(x)[2:]
    if h[-1] == 'L': # remove trailing L
        h = h[:-1]

    if len(h) & 1 == 1: # make the length even for unhexlify function
        h = '0' + h

    x = unhexlify(h)
    
    return '\x00' * int(xLen-len(x)) + x

def MGF(mgfSeed, maskLen):
    hLen = len(SHA.new("").digest())
    if maskLen > pow(2, 32) * hLen:
        print "Mask too long"
        return -1

    T = ""

    for i in range(utils.ceil(maskLen, hLen)):
        C = I2OSP(i, 4)
        T += CryptoBox.generateHash(mgfSeed + C)

    return T[:maskLen]

def stringXOR(a, b):

    return ''.join((chr(ord(x) ^ ord(y)) for (x,y) in zip(a,b)))

def numOctets(x):
    ctr = 0

    while x > 1:
        x = x / 256
        ctr += 1

    return ctr

def encrypt(N, e, message, L = ""):
    lHash = SHA.new(L).digest()
    hLen = len(lHash)
    mLen = len(message)
    k = numOctets(N)

    if mLen > k - (2*hLen) - 2:
        print "Message too long"
        return -1

    lPS = (k - mLen - 2*hLen - 2)
    PS = '\x00' * lPS
    DB = ''.join((lHash, PS, '\x01', message))

    seed = I2OSP(utils.gen_random(hLen * 8), hLen)

    dbMask = MGF(seed, k - hLen - 1)
    maskedDB = stringXOR(DB, dbMask)

    seedMask = MGF(maskedDB, hLen)
    maskedSeed = stringXOR(seed, seedMask)

    EM = ''.join(('\x00', maskedSeed, maskedDB))

    m = OS2IP(EM)

    c = RSAEP(N, e, m)

    cipherText = I2OSP(c, k)

    return cipherText

def RSADP(N, d, c):
    if c < 0 or c > N - 1:
        print "Ciphertext representative out of range"
        return

    return utils.mod_exp(c, d, N)

def decrypt(N, d, p, q, cipher_text, L = ""):
     k = numOctets(N)
     lHash = SHA.new(L).digest()
     hLen = len(lHash)

     if k != len(cipher_text) or k < 2*hLen + 2:
         print "Decryption error"
         return

     c = OS2IP(cipher_text)
     m = RSADP(N, d, c)
     if m == -1:
         return -1
     EM = I2OSP(m, k)

     if EM[0] != '\x00':
         print "Decryption error"
         return

     maskedSeed = EM[1:hLen + 1]
     maskedDB = EM[hLen + 1:]
     seedMask = MGF(maskedDB, hLen)
     seed = stringXOR(maskedSeed, seedMask)
     dbMask = MGF(seed, k - hLen - 1)
     DB = stringXOR(maskedDB, dbMask)

     oldHash = DB[:hLen]
     rest = DB[hLen:]
     i = rest.find('\x01')
     m = rest[i+1:]

     if oldHash != lHash or i == -1 or rest[:i].strip('\x00') != '':
         print "Decryption error"
         return

     return m

def EMSAPSSENC(M, emBits, sLen = 16):
    mHash = SHA.new(M).digest()
    hLen = len(mHash)
    emLen = utils.ceil(emBits, 8)
    
    if emLen < hLen + sLen + 2:
        print "Encoding error"
        return
    
    salt = I2OSP(utils.gen_random(sLen * 8), sLen)
    m_prime = '\x00' * 8 + mHash + salt
    H = SHA.new(m_prime).digest()
    PS = '\x00' * (emLen - sLen - hLen - 2)
    DB = PS + '\x01' + salt
    dbMask = MGF(H, emLen - hLen - 1)
    maskedDB = stringXOR(DB, dbMask)
    octets, bits = (8 * emLen - emBits) / 8, (8 * emLen - emBits) % 8
    maskedDB = ('\x00' * octets) + maskedDB[octets:]
    newByte = chr(ord(maskedDB[octets]) & (255 >> bits))
    maskedDB = maskedDB[:octets] + newByte + maskedDB[octets+1:]
    EM = maskedDB + H + '\xbc'

    return EM

def RSASP1(N, d, m):
    if m < 0 or m > N - 1:
        print "Message representative out of range"
        return

    return utils.mod_exp(m, d, N)

def bitSize(n):
    if n == 0:
        return 1
    s = 0
    while n:
        s += 1
        n >>= 1
    return s

def generateSignature(N, d, message):
    k = numOctets(N)
    modBits = bitSize(N)
    EM = EMSAPSSENC(message, modBits - 1)
    m = OS2IP(EM)
    s = RSASP1(N, d, m)
    S = I2OSP(s, k)
    
    return S

def RSAVP1(N, e, s):
    if s < 0 or s > N - 1:
        print "Signature representative out of range"
        return

    return utils.mod_exp(s, e, N)

def EMSAPSSVER(M, EM, emBits, sLen = 16):
    mHash = SHA.new(M).digest()
    hLen = len(mHash)
    emLen = utils.ceil(emBits, 8)

    if emLen < hLen + sLen + 2 or EM[len(EM) - 1] != '\xbc':
        print "Inconsistent"
        return False

    maskedDB, h = EM[:emLen - hLen - 1], EM[emLen - hLen - 1: -1]

    octets, bits = (8 * emLen - emBits) / 8, (8 * emLen - emBits) % 8
    zero = maskedDB[:octets] + chr(ord(maskedDB[octets]) & ~(255 >>bits))

    for c in zero:
        if c != '\x00':
            return False

    dbMask = MGF(h, emLen - hLen - 1)
    DB = stringXOR(maskedDB, dbMask)
    newByte = chr(ord(DB[octets]) & (255 >> bits))
    DB = ('\x00' * octets) + newByte + DB[octets+1:]

    for c in DB[:emLen - hLen - sLen - 2]:
        if c != '\x00':
            return False

    if DB[emLen - hLen - sLen - 2] != '\x01':
        return False

    salt = DB[-sLen:]
    m_prime = ('\x00' * 8) + mHash + salt
    h_prime = SHA.new(m_prime).digest()

    return h_prime == h

def verifySignature(N, e, message, signature):
    k = numOctets(N)
    modBits = bitSize(N)

    if len(signature) != k:
        print "Invalid signature"
        return

    s = OS2IP(signature)
    m = RSAVP1(N, e, s)
    emLen = utils.ceil((modBits -1), 8)
    EM = I2OSP(m, emLen)
    
    return EMSAPSSVER(message, EM, modBits - 1)
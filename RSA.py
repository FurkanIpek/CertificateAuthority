import utils

from random import randint
from fractions import gcd

def generateKeys(security_level): ## TODO sec_level & how to generate keys?
    p = utils.gen_random(512)

    while utils.rm_primality(p) == False:
        p = utils.gen_random(512)

    q = utils.gen_random(512)

    while utils.rm_primality(p) == False:
        q = utils.gen_random(512)

    N = p * q

    phi_N = (p-1) * (q-1)

    e = randint(1, phi_N - 1)

    while gcd(e, phi_N) != 1:
        e = randint(1, phi_N - 1)

    d = utils.inverse(e, phi_N)

    return e, N, d, p, q

def OS2IP(str): # TODO
    length = len(str)
    value = 0

    for i in range(length):
        value += int(str[i]) * pow(256, i)

    return value


def RSAEP(N, e, m):
    if m < 0 or m > n - 1:
        print "Message representative out of range!"
        return -1

    c = utils.mod_exp(m, e, N)

    return c


def I2OSP(x, xLen): #TODO
    if x >= pow(256, xLen):
        print "Integer too large"
        return -1

    arr = [ 0 for i in range(xLen) ]

    for i in range(xLen):
        arr[i] = x / pow(256, xLen-i)

    output = ""

    for i in range(xLen):
        output += str(arr[i])

    return output


def MGF(mgfSeed, maskLen):
    if maskLen > pow(2, 32):
        print "Mask too long"
        return

    hLen = len(utils.generateHash("length", 1))
    T = ""

    for i in range(maskLen/hLen - 1):
        C = I2OSP(i, 4)
        T += utils.generateHash(mgfSeed + C)

    output = ""

    for i in range(maskLen):
        output += T[i]

    return output


def encrypt(N, e, message, security_level, L = ""):
    lHash = utils.generateHash(L, 1) # TODO lHash = hash(L)
    hLen = len(lHash)
    mLen = len(message)
    k = len(str(N())) # TODO check correctness # k = octet length of modulus N

    PS = ""
    for i in range(k - mLen - 2*hLen - 2):
        PS += "0"

    DB = lHash + PS + chr(1) + message # TODO 0x01 == chr(1) ?

    seed = ""
    for i in range(hLen):
        seed += chr(randint(0, 255))

    dbMask = MGF(seed, k - hLenn - 1)
    maskedDB = DB ^ dbMask

    seedMask = MGF(maskedDB, hLen)
    maskedSeed = seed ^ seedMask

    encryptedMessage = chr(0) + maskedSeed + maskedDB # TODO 0x00 == chr(0) ?

    m = OS2IP(encryptedMessage)

    c = RSAEP(N, e, m)

    cipherText = I2OSP(c, k)

    return cipherText



def RSADP(N, d, c):
    if c < 0 or c > n - 1:
        print "Ciphertext representative out of range"
        return -1

    m = utils.mod_exp(c, d, N)

    return m


def decrypt(N, d, p, q, cipher_text, L = ""):
     k = len(str(N))
     hLen = len(utils.generateHash("length", 1))

     if k != len(cipher_text) or k < 2*hLen + 2:
         print "Decryption error"
         return -1

     c = OS2IP(cipher_text)
     m = RSADP(N, d, c)
     if m == -1:
         return -1
     EM = I2OSP(m, k)
     
     lHash = utils.generateHash(L, 1)
     hLen = len(lHash)

     maskedSeed = ""
     for i in range(hLen):
         maskedSeed += EM[1 + i]

     maskedDB = EM[hLen + 1:]
     seedMask = NGF(maskedDB, hLen)
     seed = maskedSeed ^ seedMask
     dbMask = MGF(seed, k - hLen - 1)
     DB = maskedDB ^ dbMask

     state = False
     message = ""
     for i in range(len(DB) - hLen):
         if DB[hLen + i] == 0:
             continue
         elif DB[hLen + i] == 1:
             state = True

         if state:
             message += DB[hLen + i]

     if state == False:
         print "Decryption error"
         return -1

     return message


def generateSignature(): # TODO
     print "TODO"


def verifySignature(): # TODO
     print "TODO"
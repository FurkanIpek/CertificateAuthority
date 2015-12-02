
import utils
import RSA

from binascii import unhexlify

from Crypto.Hash import SHA256

if __name__ == "__main__":
    message = "Hey there! The angel from my nightmare!"

    #result = utils.AESencryption(message, 1)
    #ori_m = utils.AESdecryption(result[0], result[1], result[2])
    #print ori_m

    #result = utils.DES3encryption(message)
    #ori_m = utils.DES3decryption(result[0], result[1], result[2])
    #print ori_m

    #hash1 = utils.generateHash(message, 1)
    #print hash1

    #bigint = utils.gen_random(1024)
    #print utils.rm_primality(bigint)
    #print "to str: ", len(str(bigint))

    #os2ip = RSA.OS2IP("123123")
    #i2osp = RSA.I2OSP(os2ip, 6)

    #print os2ip, i2osp

    keys = RSA.generateKeys(1)
    e, N, d, p, q = keys[0], keys[1], keys[2], keys[3], keys[4]
    phi_N = (p-1) * (q-1)

    print N == p * q
    print (e * d) % phi_N
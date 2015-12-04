from CryptographicAlgorithms import CryptoBox
from binascii import hexlify, unhexlify
from Reader import Reader

if __name__ == "__main__":

    security_level = 1

    fileManager = Reader()
    fileManager.read()

    res = hexlify(CryptoBox.generateHash(fileManager.inputs[fileManager.SHA], 1)) # SHA256
    fileManager.write("# SHA256\n" + res + "\n")
    res = hexlify(CryptoBox.generateHash(fileManager.inputs[fileManager.SHA], 2)) # SHA384
    fileManager.write("# SHA384\n" + res + "\n")
    res = hexlify(CryptoBox.generateHash(fileManager.inputs[fileManager.SHA], 3)) # SHA512
    fileManager.write("# SHA512\n" + res + "\n")

    AES_cipher = CryptoBox.AESencryption(fileManager.inputs[fileManager.AES], 1) # AES enc & dec
    key, cipher, iv = AES_cipher[0], AES_cipher[1], AES_cipher[2]
    AES_original = CryptoBox.AESdecryption(key, cipher, iv)
    fileManager.write("\n# AES security level " + str(security_level)
                 + "\nkey = " + hexlify(key) + "\ncipher text = " + hexlify(cipher) + "\niv = " + hexlify(iv)
                 + "\noriginal text = " + hexlify(AES_original) + "\n")

    DES3_cipher = CryptoBox.DES3encryption(fileManager.inputs[fileManager.DES3]) # DES3 enc & dec
    key, cipher, iv = DES3_cipher[0], DES3_cipher[1], DES3_cipher[2]
    DES3_original = CryptoBox.DES3decryption(key, cipher, iv)
    fileManager.write("\n# 3DES"
                 + "\nkey = " + hexlify(key) + "\ncipher text = " + hexlify(cipher) + "\niv = " + hexlify(iv)
                 + "\noriginal text = " + hexlify(DES3_original)+ "\n")

    # Generate ElGamal and DSA keys
    keys = CryptoBox.ElGamalAndDSAKeyGeneration(security_level)
    p, q, g, x, y = keys[0], keys[1], keys[2], keys[3], keys[4]

    DSA_sign = CryptoBox.DSAGenerateSignature(p, q, g, x, fileManager.inputs[fileManager.DSA]) # DSA signature gen & ver
    r, s = DSA_sign[0], DSA_sign[1]
    DSA_verified = CryptoBox.DSAVerifySignature(p, q, g, y, r, s, fileManager.inputs[fileManager.DSA])
    fileManager.write("\n# DSA signature generation & verification"
                 + "\n p, q, g, public, private = " + str(p) + " " + str(q) + " " + str(g)
                 + " " + str(x) + " " + str(y)
                 + "\n r, s = " + str(r) + " " + str(s) + " and verified = " + str(DSA_verified) + "\n")

    ElGamal_enc = CryptoBox.ElGamalEncryption(p, q, g, y, int(fileManager.inputs[fileManager.ELGAMAL])) # ElGamal enc & dec
    r, t = ElGamal_enc[0], ElGamal_enc[1]
    ElGamal_original = CryptoBox.ElGamalDecryption(p, q, x, r, t)
    fileManager.write("\n# ElGamal encryption & decryption"
                 + "\nr, t = " + str(r) + " " + str(t)
                 + "\nOriginal text = " + str(ElGamal_original) 
                 + "\nOriginal as hex = " + hexlify(str(ElGamal_original)) + "\n")

    # Generate RSA keys
    keys = CryptoBox.RSAKeyGeneration(security_level)
    e, N, d, p, q = keys[0], keys[1], keys[2], keys[3], keys[4]
    L = "somel"

    RSA_cipher = CryptoBox.RSAencryption(N, e, fileManager.inputs[fileManager.RSA], L)
    RSA_original = CryptoBox.RSAdecryption(N, d, p, q, RSA_cipher, L)
    fileManager.write("\n# RSA encryption & decryption"
                      + "\ncipher text = " + hexlify(RSA_cipher)
                      + "\noriginal text = " + RSA_original
                      + "\noriginal as hex = " + hexlify(RSA_original) + "\n")

    RSA_sign = CryptoBox.RSAGenerateSignature(N, d, fileManager.inputs[fileManager.RSAverification])
    RSA_verified = CryptoBox.RSAVerifySignature(N, e, fileManager.inputs[fileManager.RSAverification], RSA_sign)
    fileManager.write("\n# RSA signature generation & verification"
                      + "\nsignature = " + hexlify(RSA_sign)
                      + "\nverified = " + str(RSA_verified) + "\n")
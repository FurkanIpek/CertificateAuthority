from CryptographicAlgorithms import CryptoBox

from binascii import hexlify, unhexlify

# TODO from test vector, read hex input. Then unhexlify it and send to the CryptoBox
if __name__ == "__main__":
    message = "Hello there! The angel from my nightmare!"
    security_level = 1
    L = "some l"
    
    # Generate RSA keys
    keys = CryptoBox.RSAKeyGeneration(security_level)
    e, N, d, p, q = keys[0], keys[1], keys[2], keys[3], keys[4]

    # RSA encryption & decryption example
    cipher_text =  CryptoBox.RSAencryption(N, e, message, L)
    print CryptoBox.RSAdecryption(N, d, p, q, cipher_text, L)

    # RSA signature generation & verification example
    signature = CryptoBox.RSAGenerateSignature(N, d, message)
    print CryptoBox.RSAVerifySignature(N, e, message, signature)

    # Generate ElGamal and DSA keys
    keys = CryptoBox.ElGamalAndDSAKeyGeneration(security_level)
    p, q, g, x, y = keys[0], keys[1], keys[2], keys[3], keys[4]

    # DSA signature generation and verification example
    signatures = CryptoBox.DSAGenerateSignature(p, q, g, x, message)
    r, s = signatures[0], signatures[1]
    print CryptoBox.DSAVerifySignature(p, q, g, y, r, s, message)

    # ElGamal encryption & decryption example
    message = 123
    res = CryptoBox.ElGamalEncryption(p, q, g, y, message)
    r, t = res[0], res[1]
    print CryptoBox.ElGamalDecryption(p, q, x, r, t)
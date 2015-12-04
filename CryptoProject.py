from CryptographicAlgorithms import CryptoBox

# TODO from test vector, read hex input. Then unhexlify it and send to the CryptoBox
if __name__ == "__main__":
    message = "Hello there! The angel from my nightmare!"

    keys = CryptoBox.RSAencryption(message, 1)
    e, N, d, p, q, cipher_text = keys[0], keys[1], keys[2], keys[3], keys[4], keys[5]
    print CryptoBox.RSAdecryption(N, d, p, q, cipher_text)

    keys = CryptoBox.RSAGenerateSignature(message, 1)
    e, N, d, p, q, signature = keys[0], keys[1], keys[2], keys[3], keys[4], keys[5]
    print CryptoBox.RSAVerifySignature(N, e, message, signature)

    keys = CryptoBox.DSAGenerateSignature(message, 1)
    p, q, g, x, y, r, s = keys[0], keys[1], keys[2], keys[3], keys[4], keys[5], keys[6]
    print CryptoBox.DSAVerifySignature(p, q, g, y, r, s, message)

    message = 123
    keys = CryptoBox.ElGamalEncryption(message, 1)
    p, q, g, x, y, r, t = keys[0], keys[1], keys[2], keys[3], keys[4], keys[5], keys[6]
    print CryptoBox.ElGamalDecryption(p, q, x, r, t)
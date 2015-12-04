from binascii import unhexlify, hexlify

class Reader(object):
    """Reads test vectors from file_in, and capable of writing to file_out"""

    file_in = None
    file_out = None
    size = None
    inputs = None

    SHA = 0
    AES = 1
    DES3 = 2
    DSA = 3
    ELGAMAL = 4
    RSA = 5
    RSAverification = 6

    def __init__(self, file_in = 'TestVectors.tv', file_out = 'TestOuts.tv'):
        self.file_in = file_in
        self.file_out = file_out
        #Create inputs array accordingly to test vector input size
        file = open(self.file_in, 'r')
        self.size = int(file.readline()[:-1])
        file.close()
        self.inputs = [ None for i in range(self.size) ]
        # Clear the file_out
        open(self.file_out, 'w').close

    def read(self):
        file = open(self.file_in, 'r')
        file.readline() # eat up the line with sizxe info

        for i in range(self.size):
            var = file.readline() # eat up comment
            var = str(file.readline()[:-1]).replace(' ', '')
            if len(var) & 1 == 1:
                print "Not a hexadecimal string on input num " , i + 1
                var = file.readline() # eat up empty line
                continue
            self.inputs[i] = unhexlify(var)
            var = file.readline() # eat up empty line

        file.close()

    def write(self, message):
        file = open(self.file_out, 'a')
        file.write(message)
        file.close()

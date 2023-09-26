#
# a wrapper module for pycryptodome.
#
from Crypto.Cipher import AES

class AES_ECB():
    def __init__(self, key):
        """
        key: 8 bytes of bytearray
        """
        self.aes_ecb = AES.new(key, AES.MODE_ECB)

    def encrypt(self, data):
        """
        data: any size of bytearray. expanded into 16 bytes if less.
        """
        blk_list = []
        for i in range(0,len(data),16):
            blk = data[i:i+16]
            blk += b"\x00"*(16-len(blk))
            blk_list.append(self.aes_ecb.encrypt(bytes(blk)))
        return b"".join(blk_list)

    def decrypt(self, enc_data):
        """
        enc_data: in bytearray, must be multiple of 16.
        """
        blk_list = []
        for i in range(0,len(enc_data),16):
            blk_list.append(self.aes_ecb.decrypt(enc_data[i:i+16]))
        return b"".join(blk_list)

def aes128_encrypt(key, plain_data):
    """
    one time encryper.
    it's used mainly for key generation.
        key: in bytes.
        plain_data: in bytes.
    """
    cipher = AES_ECB(key)
    return cipher.encrypt(plain_data)

def aes128_decrypt(key, enc_data):
    """
    one time encryper.
    it's used mainly for key generation.
        key: in bytes.
        plain_data: in bytes.
    """
    cipher = AES_ECB(key)
    return cipher.decrypt(enc_data)


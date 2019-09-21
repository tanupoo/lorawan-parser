from Crypto.Hash import CMAC
from Crypto.Cipher import AES

class AES_CMAC():
    """
    >>> cmac = AES_CMAC(b'Sixteen byte key')
    >>> cmac.update(b'Hello')
    >>> print(cmac.hex(upper=True))
    8E1A0ED893AB9A3D891CDEF2878CDB59
    """
    def __init__(self, key):
        self.cmac = CMAC.new(key, ciphermod=AES)

    def update(self, data):
        self.cmac.update(data)

    def digest(self):
        return self.cmac.digest()

    def hex(self, upper=False):
        if upper:
            return self.cmac.hexdigest().upper()
        else:
            return self.cmac.hexdigest()

"""
RFC 4493

   --------------------------------------------------
   Subkey Generation
   K              2b7e1516 28aed2a6 abf71588 09cf4f3c
   AES-128(key,0) 7df76b0c 1ab899b3 3e42f047 b91b546f
   K1             fbeed618 35713366 7c85e08f 7236a8de
   K2             f7ddac30 6ae266cc f90bc11e e46d513b
   --------------------------------------------------

   --------------------------------------------------
   Example 1: len = 0
   M              <empty string>
   AES-CMAC       bb1d6929 e9593728 7fa37d12 9b756746
   --------------------------------------------------

   Example 2: len = 16
   M              6bc1bee2 2e409f96 e93d7e11 7393172a
   AES-CMAC       070a16b4 6b4d4144 f79bdd9d d04a287c
   --------------------------------------------------

   Example 3: len = 40
   M              6bc1bee2 2e409f96 e93d7e11 7393172a
                  ae2d8a57 1e03ac9c 9eb76fac 45af8e51
                  30c81c46 a35ce411
   AES-CMAC       dfa66747 de9ae630 30ca3261 1497c827
   --------------------------------------------------

   Example 4: len = 64
   M              6bc1bee2 2e409f96 e93d7e11 7393172a
                  ae2d8a57 1e03ac9c 9eb76fac 45af8e51
                  30c81c46 a35ce411 e5fbc119 1a0a52ef
                  f69f2445 df4f9b17 ad2b417b e66c3710
   AES-CMAC       51f0bebf 7e3b9d92 fc497417 79363cfe
   --------------------------------------------------
"""
if __name__ == "__main__":
    def s2b(s):
        return bytearray.fromhex(s.replace(" ",""))
    #
    test_vectors = [
            { "M": "",
              "A": "bb1d6929 e9593728 7fa37d12 9b756746" },
            { "M": "6bc1bee2 2e409f96 e93d7e11 7393172a",
              "A": "070a16b4 6b4d4144 f79bdd9d d04a287c" },
            { "M": """
             6bc1bee2 2e409f96 e93d7e11 7393172a
             ae2d8a57 1e03ac9c 9eb76fac 45af8e51
             30c81c46 a35ce411""",
              "A": "dfa66747 de9ae630 30ca3261 1497c827" },
            { "M": """
             6bc1bee2 2e409f96 e93d7e11 7393172a
             ae2d8a57 1e03ac9c 9eb76fac 45af8e51
             30c81c46 a35ce411 e5fbc119 1a0a52ef
             f69f2445 df4f9b17 ad2b417b e66c3710""",
              "A": "51f0bebf 7e3b9d92 fc497417 79363cfe" }
            ]
    K = "2b7e1516 28aed2a6 abf71588 09cf4f3c"
    for v in test_vectors:
        cmac = AES_CMAC(s2b(K))
        cmac.update(s2b(v["M"]))
        print(cmac.hex(), end=" ")
        if s2b(v["A"]) == cmac.digest():
            print("OK")
        else:
            print("ERROR")


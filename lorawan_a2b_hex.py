import re
from base64 import b64decode

def a2b_hex(buf, string_type="hexstr"):
    """
    buf must be in several types of hex string.
    return a hex string.
    """
    if buf is None:
        return None
    if isinstance(buf, list):
        buf = "".join(buf)
    if string_type == "base64":
        return bytearray(b64decode(buf))
    elif "." in buf:
        # in case like "a4.9.0.19"
        hexstr = "".join([i.rjust(2,"0") for i in buf.split(".")])
    else:
        # others
        hexstr = re.sub(r"([,\s\n]|0x)", "", buf)
    if len(hexstr)%2 == 1:
        raise ValueError("the length of hexstr is not even. len={} hexstr={}"
                         .format(len(hexstr), hexstr))
    return bytearray.fromhex(hexstr)

if __name__ == "__main__":
    test_list = [
        "402105810080160102a6bf4432169ea0784416868d9420dd244619443e",
        "40C1D25201A5050003070703120864FE226A9E",
        "40C1, D252, 01A5, 0500, 0307, 0703, 1208, 64FE, 226A, 9E",
        "40C1 D252 01A5 0500 0307 0703 1208 64FE 226A 9E",
        "0x40 0xC1 0xD2 0x52 0x01 0xA5 0x05 0x00 0x03 0x07 0x07 0x03 0x12 0x08 0x64 0xFE 0x22 0x6A 0x9E",
        "0x40,0xC1,0xD2,0x52,0x01,0xA5,0x05,0x00,0x03,0x07,0x07,0x03,0x12,0x08,0x64,0xFE,0x22,0x6A,0x9E",
        "66.8c.cc.57.8a.a4.a4.9.0.19.14.10.0.8.0.0.a0.ad.ba.0.0.0.7.0.b.81.b0.bf.b6.d9.f1.ca.44.b4.7c.2c",
        ]
    for d in test_list:
        print("*  ", d)
        print(" =>", a2b_hex(d).hex())
    d = "IM7jjKOUkVEf405egXcnkBPNCoKH6CIUgJgY5Op90XmQ"
    print("*  ", d)
    print(" =>", a2b_hex(d, string_type="base64").hex())

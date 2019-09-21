from aes_ecb import aes128_encrypt
from aes_ecb import AES_ECB
from aes_cmac import AES_CMAC

# Note:
#     The arguments of the following functions are ordered in big endian.
#     The return value is ordered in big endian as well.
# Assumption:
#     The the length of multiple bytes (including odds bytes) of values
#     passing to aes-ccm* must be in little endian.
#     e.g.
#     The devaddr is "12345678", which is "78563412" in the wire format.
#     It should be formed to "78563412" to pass it into the aes-ccm*.

UP_LINK = 0
DOWN_LINK = 1

def lorawan_frmp_encryption(key, msg, devaddr, msg_dir, fcnt):
    """
    LoRaWAN FRM Payload encoder/decoder in AES128-CCM-STAR.
        key: the size must be 16 bytes.
        msg: message to be encrypted.
        devaddr: DevAddr, the size must be 4 bytes, in big endian.
        msg_dir: UP_LINK(=0) or DOWN_LINK(=1)
        fcnt: FCnt, the size must be 4 bytes, in big endian.
            i.e. 16-bit maintained value + 16-bit in the payload.
    This function refers to:
    - 4.3.3 MAC Frame Payload Encryption (FRMPayload)
    - LoRaMacPayloadEncrypt() in Lora-net/LoRaMac-node.
        https://github.com/Lora-net/LoRaMac-node/blob/master/src/mac/LoRaMacCrypto.c#L108
    """
    Ai = bytearray(16)
    Ai[0] = 0x01
    Ai[5] = msg_dir
    # put both devaddr and fcnt in little endian.
    Ai[6] = devaddr[3]
    Ai[7] = devaddr[2]
    Ai[8] = devaddr[1]
    Ai[9] = devaddr[0]
    Ai[10] = fcnt[3]
    Ai[11] = fcnt[2]
    Ai[12] = fcnt[1]
    Ai[13] = fcnt[0]

    size = len(msg)
    buf = bytearray(size)
    offset = 0
    ctr = 1

    cipher = AES_ECB(key)

    while size >= 16:
        Ai[15] = ctr & 0xff
        ctr += 1
        Si = cipher.encrypt(Ai)
        for i in range(16):
            buf[offset + i] = msg[offset + i] ^ Si[i]
        size -= 16
        offset += 16

    if size > 0:
        Ai[15] = ctr & 0xff
        Si = cipher.encrypt(Ai)
        for i in range(size):
            buf[offset + i] = msg[offset + i] ^ Si[i]

    return buf

def lorawan_frmp_integrity(key, msg, devaddr, msg_dir, fcnt):
    """
    LoRaWAN FRM Payload integrity.
        key: the size must be 16 bytes.
        msg: message to be encrypted.
        devaddr: DevAddr, the size must be 4 bytes, in big endian.
        msg_dir: UP_LINK(=0) or DOWN_LINK(=1)
        fcnt: FCnt, the size must be 4 bytes, in big endian.
            i.e. 16-bit maintained value + 16-bit in the payload.
    This function refers to:
    - 4.4 Message Integrity Code (MIC)
    """
    B0 = bytearray(16)
    B0[0] = 0x49
    B0[5] = msg_dir
    # put both devaddr and fcnt in little endian.
    B0[6] = devaddr[3]
    B0[7] = devaddr[2]
    B0[8] = devaddr[1]
    B0[9] = devaddr[0]
    B0[10] = fcnt[3]
    B0[11] = fcnt[2]
    B0[12] = fcnt[1]
    B0[13] = fcnt[0]
    B0[15] = len(msg)

    return lorawan_aes128_cmac(key, B0 + msg)

def lorawan_aes128_encrypt(key, msg):
    """
    encrypt data of LoRaWAN message.
        key, msg: in bytearray
        return: message decrypted in bytearray
    """
    return aes128_encrypt(key, msg)

#def lorawan_decrypt(key_hex, msg_hex):
#    """
#    decrypt data of LoRaWAN message.
#        key, msg: in bytearray
#        return: message encrypted in bytearray.
#    """
#    return aes128_decrypt(key, msg)

def lorawan_aes128_cmac(key, msg):
    """
    calculating the MIC.
        key, msg: in bytearray.
        return: 4 bytes MIC.
    """
    #key = bytearray.fromhex(key_hex)
    cmac = AES_CMAC(key)
    #cmac = AES_CMAC(bytearray.fromhex(key_hex))
    cmac.update(msg)
    m = cmac.digest()
    return {
            "mic": m[:4][::-1],
            "cmac": m
            }

def lorawan_get_keys(appkey, devnonce=None, appnonce=None, netid=None):
    """
    Generating LoRaWAN Keys for v1.0.x.
        all arguments are in bytearray.
        devnonce, appnonce, netid are in big endian.
        return is a dict like { "nwkskey": NwkSKey, "appskey": AppSKey }

    v1.0.2
    NwkSKey = aes128_encrypt(AppKey, 0x01 | AppNonce | NetID | DevNonce | pad16)
    AppSKey = aes128_encrypt(AppKey, 0x02 | AppNonce | NetID | DevNonce | pad16)
    """
    base_data = appnonce[::-1] + netid[::-1] + devnonce[::-1]
    pad16 = b"\x00"*(16-(1+len(base_data))%16)
    buf = b"\x01" + base_data + pad16
    nwkskey = aes128_encrypt(appkey, b"\x01" + base_data + pad16)
    appskey = aes128_encrypt(appkey, b"\x02" + base_data + pad16)
    #
    return {
            "nwkskey": nwkskey,
            "appskey": appskey,
            }

if __name__ == "__main__" :
    # 1.2 Conventions, v1.0.3
    #     The octet order for all multi-octet fields is little endian and
    #     EUI are 8 bytes multi-octet fields and are transmitted
    #     as little endian.
    mic_test = [
        # AppEUI  : 0000000000000000
        # DevEUI  : 0050AB8195000001
        # AppKey  : 00000000000000000000000000000000
        # wire    : 00 0000000000000000 0100009581AB5000 17E3 9FADBC6E
        {
        "cmt": "OK: wire format (little endian) as it is.",
        "msg": "00" + "0000000000000000" + "0100009581AB5000" + "17E3",
        "mic": "6EBCAD9F",
        "appkey": "00000000000000000000000000000000"
        },
        {
        "cmt": "NG: big endian.",
        "msg": "00" + "0000000000000000" + "0050AB8195000001" + "E317",
        "mic": "9FADBC6E",
        "appkey": "00000000000000000000000000000000"
        },
        # MIC is calculated by
        #     MIC = aes128_cmac(Appkey, MHDR | Join-Accept)
        # Join-Accept + MIC are encrypted by:
        #     aes128_decrypt(AppKey, Join-Accept | MIC)
        # e.g.
        # wire     : 20 ED8D1A 7B11EA CDD3F52D FC 39 0FFF77E2
        # Decrypted:    248870 010000 248DE503 02 01 88639B03
        # MIC is 039B6388
        # 
        {
        "cmt": "NG: wire format as it is.",
        "msg": "20" + "ED8D1A" + "7B11EA" + "CDD3F52D" + "FC" + "39",
        "mic": "E277FF0F",
        "appkey": "00000000000000000000000000000000"
        },
        {
        "cmt": "OK: wire format (little endian) and decrypted.",
        "msg": "20" + "248870" + "010000" + "248DE503" + "02" + "01",
        "mic": "039B6388",
        "appkey": "00000000000000000000000000000000"
        },
        {
        "cmt": "NG: big endian.",
        "msg": "20" + "708824" + "000001" + "03E58D24" + "02" + "01",
        "mic": "4CCDA3CA",
        "appkey": "00000000000000000000000000000000"
        },
    ]
    # Join Response message.
    for d in mic_test:
        data = bytearray.fromhex(d["msg"])
        appkey = bytearray.fromhex(d["appkey"])
        mic_deriv = lorawan_aes128_cmac(appkey, data)["mic"].hex()
        mic_given = d["mic"].lower()
        print("## {}".format(d["cmt"]))
        print("data len={}: {}".format(len(data), data.hex()))
        print("appkey:", appkey.hex())
        print("mic_deriv:", mic_deriv)
        print("mic_given:", mic_given)
        print("")

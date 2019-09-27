import sys
import re
import argparse
import binascii
from lorawan_cipher import lorawan_aes128_cmac
from lorawan_cipher import lorawan_aes128_encrypt
from lorawan_cipher import lorawan_frmp_encryption
from lorawan_cipher import lorawan_frmp_integrity
from lorawan_a2b_hex import a2b_hex
import textwrap

# NOTE:
#   In LoRaWAN, the network byte order is little endian.
#   Each 2, 4, 8 bytes field must be read as little endian.
# Assumption:
#   LoRaWAN wire format is in little endian.

# Convention:
#   variable_x: a bytearray
#   variable_i: a int
#   variable_b: a bit string
#   variable_o: a dict
#   buf, payload, phy_pdu, *key, devaddr, mic*: a byte array.
#
#   however, no postfix usually means that the variable is in bytearray.
#   so, needs to understand the context.

MSGDIR_DOWN = 1
MSGDIR_UP = 0
MSGDIR_UNKNOWN = 99
__MIC_SIZE = 4

opt = type("DEFAULT_OPTION",(object,),{"debug_level":0, "verbose":False})
__parse_only = False

#====

def formx(v, form=None):
    """
    convert a value into a string with a type of value.
    """
    if isinstance(v, int) and form == "hz":
        return "{} kHz".format(v)
    elif isinstance(v, int) and form == "sec":
        return "{} sec".format(v)
    elif isinstance(v, int) and form == "pff":
        if v == 0:
            return "Connected to an external power source."
        elif v == 255:
            return "No ability to measure the level."
        else:
            return "{} %".format((v-1)/253*100)
    elif isinstance(v, int):
        return "x {:02x}".format(v)
    elif isinstance(v, (bytes,bytearray)):
        return "x {}".format(v.hex())
    elif isinstance(v, str) and form == "bin":
        return "b {}".format(v)
    else:
        raise ValueError("ERROR: unsupported arg for formx, {} type={}"
                         .format(v,type(v)))

def x2bin(v):
    """
    convert a value into a binary string
        v: int, bytes, bytearray
    bytes, bytearray must be in *big* endian.
    """
    if isinstance(v, int):
        bits = bin(v)
        size = 8
    elif isinstance(v, (bytes,bytearray)):
        bits = bin(int.from_bytes(v, "big"))
        size = len(v)*8
    return bits[2:].zfill(size)

def x2int(v):
    """
    convert a value into an int.
        v: bit string, bytes, bytearray
    bytes, bytearray must be in little endian.
    """
    if isinstance(v, str) and set(v) in [{"0"},{"1"},{"0","1"}]:
        return int(v, 2)
    elif isinstance(v, (bytes, bytearray)):
        return int.from_bytes(v, "little")

def print_detail(text):
    """
    mainly print description for MAC Command.
    """
    if not opt.verbose:
        return
    indent = 10
    bullet = "* DETAIL:"
    bullet_len = 1 + len(bullet)
    print(textwrap.fill(text, width=75,
                        initial_indent="{}{}".format(" "*indent, bullet),
                        subsequent_indent="{}".format(" "*(indent+bullet_len))))

def print_vt(tag, v_wire=None, v_bits=None, indent=0):
    """
    print a value with tag as a title.
        tag: string.
        v_wire: string or None, usually wire format in bytes.
        v_bits: string or None, usually bits.
    """
    if __parse_only is True:
        return
    bullet = " "*(2*indent) + "#"*(2+indent)
    print("{} {}".format(bullet, tag), end="")
    if v_wire not in ["", None]:
        print(" : {}".format(v_wire), end="")
    if opt.verbose and v_bits not in ["", None]:
        print(" [{}]".format(v_bits), end="")
    print("")

def print_v(tag, v_host=None, v_wire=None, indent=1, debug=False):
    """
    print a value with tag.
        tag: string.
        v_host: string of human readable, or None.
        v_wire: string in the wire, or None.
        indent: 1, 2, or 3
    """
    if __parse_only is True:
        return
    if debug and opt.debug_level == 0:
        # ignore print_d() when the -d option is not specified.
        return
    print("{}".format("  "*indent), end="")
    if debug:
        print("- DEBUG: ", end="")
    print("{}".format(tag), end="")
    if v_host not in ["", None]:
        print(" : {}".format(v_host), end="")
    if opt.verbose and v_wire not in ["", None]:
        print(" [{}]".format(v_wire), end="")
    print("")

def print_d(tag, v_host, v_wire=None, indent=1):
    print_v(tag, v_host, v_wire=v_wire, indent=indent, debug=True)

def print_w(msg):
    if opt.verbose:
        print("WARNING: {}".format(msg))

#====

def parse_macsubcmd_dwelltime(b):
    return "No Limit" if b == "0" else "400 ms"

def parse_macsubcmd_Frequency(freq_x, indent=3):
    """
    frequency encoding parser
        freq_x: 3 bytes
    it is called by:
        - parse_maccmd_NewChannelReq()
        - parse_maccmd_PingSlotChannelReq()
    """
    if len(freq_x) != 3:
        raise ValueError("length of freq_x must be 3 bytes, but {}."
                         .format(len(freq_x)))
    freq_i = x2int(freq_x)
    if freq_i == 0:
        print_v("Frequency", "disabled", formx(freq_x), indent=indent)
    else:
        print_v("Frequency", formx(freq_i,"hz"), formx(freq_x), indent=indent)

def parse_macsubcmd_DeviceMode_class(class_i):
    """
    class_i: 1 byte
    """
    if class_i == 0x00:
        print_v("Class", "A", formx(class_i), indent=3)
    elif class_i == 0x01:
        print_v("Class", "RFU", formx(class_i), indent=3)
    elif class_i == 0x02:
        print_v("Class", "C", formx(class_i), indent=3)
    else:
        print_v("Class", "Unknown", formx(class_i), indent=3)

def parse_macsubcmd_ServDev_LoRaWAN_version(ver_x):
    Dev_LoRaWAN_version_b = x2bin(ver_x)
    rfu_b = Dev_LoRaWAN_version_b[0:4]
    Minor_b = Dev_LoRaWAN_version_b[4:8]
    Minor_i = x2int(Minor_b)
    if Minor_i == 1:
        vs = "LoRaWAN x.1"
    else:
        vs = "RFU"
    print_v("Dev_LoRaWAN_version", formx(ver_x),
            formx(Dev_LoRaWAN_version_b,"bin"), indent=3)
    print_v("RFU", formx(rfu_b,"bin"), indent=3)
    print_v("Minor", vs, formx(Minor_b,"bin"), indent=4)

#===

def parse_maccmd_ResetInd(mac_cmd):
    parse_macsubcmd_ServDev_LoRaWAN_version(mac_cmd[0:1])
    print_detail("IS SUPPORTED BY V1.1 OR LATER.")
    print_detail("""
This MAC command is only available to ABP devices activated on a LoRaWAN1.1
compatible network server. LoRaWAN1.0 servers do not implement this MAC
command OTA devices MUST NOT implement this command. The network server SHALL
ignore the ResetInd command coming from an OTA device.
With the ResetInd command, an ABP end-device indicates to the network
that it has been re-initialized and
that he has switched back to its default MAC & radio parameters
""")

def parse_maccmd_ResetConf(mac_cmd):
    parse_macsubcmd_ServDev_LoRaWAN_version(mac_cmd[0:1])
    print_detail("IS SUPPORTED BY V1.1 OR LATER.")
    print_detail("""
The server's version carried by the ResetConf must be the same
than the device's version.  Any other value is invalid.
""")

def parse_maccmd_LinkCheckReq(mac_cmd):
    # zero length
    pass

def parse_maccmd_LinkCheckAns(mac_cmd):
    Margin_x = mac_cmd[0:1]
    GwCnt_x = mac_cmd[1:2]
    # Margin
    Margin_i = x2int(Margin_x)
    print_v("Margin", Margin_i, formx(Margin_x), indent=3)
    print_detail("""
The demodulation margin (Margin) is an 8-bit unsigned integer
in the range of 0..254
indicating the link margin in dB of the last successfully
received LinkCheckReq command.
A value of 0 means that the frame was received at the demodulation floor
(0 dB or no 948 margin) 
""")
    # GwCnt
    GwCnt_i = x2int(GwCnt_x)
    print_v("GwCnt", GwCnt_i, formx(GwCnt_x), indent=3)
    print_detail("""
The gateway count (GwCnt) is the number of gateways that successfully
received the last LinkCheckReq command.
""")

def parse_maccmd_LinkADRReq(mac_cmd):
    DataRate_TXPower_x = mac_cmd[0:1]
    ChMask_x = mac_cmd[1:3]
    Redundancy_x = mac_cmd[3:4]
    # DataRate_TXPower
    DataRate_TXPower_b = x2bin(DataRate_TXPower_x)
    datarate_b = DataRate_TXPower_b[0:4]
    txpower_b = DataRate_TXPower_b[4:8]
    datarate_i = x2int(datarate_b)
    txpower_i = x2int(txpower_b)
    print_v("DataRate_TXPower", formx(DataRate_TXPower_x),
            formx(DataRate_TXPower_b,"bin"), indent=3)
    print_v("DataRate", datarate_i, formx(datarate_b,"bin"), indent=4)
    print_v("TXPower", txpower_i, formx(txpower_b,"bin"), indent=4)
    print_detail("""
REGION SPECIFIC.
A value 0xF (15 in decimal format) of either DataRate or TXPower
means that the device MUST
ignore that field, and keep the current parameter value.
""")
    # ChMask
    ChMask_b = x2bin(ChMask_x)
    print_v("ChMask", formx(ChMask_x), formx(ChMask_b,"bin"), indent=3)
    for i in range(16):
        if ChMask_b[i]== "1":
            print_v("CH {}".format(i), "use", indent=4)
    print_detail("""
The channel mask (ChMask) encodes the channels usable for uplink access.
A bit in the ChMask field set to 1 means that the corresponding channel
can be used for uplink transmissions if this channel allows the data rate
currently used by the end-device.
A bit set to 0 means the corresponding channels should be avoided.
""")
    # Redundancy
    Redundancy_b = x2bin(Redundancy_x)
    rfu_b = Redundancy_b[0:1]
    ChMaskCntl_b = Redundancy_b[1:4]
    NbTrans_b = Redundancy_b[4:8]
    NbTrans_i = x2int(NbTrans_b)
    print_v("Redundancy", formx(Redundancy_x), formx(Redundancy_b,"bin"),
            indent=3)
    print_v("RFU", formx(rfu_b,"bin"), indent=4)
    print_v("ChMaskCntl", formx(ChMaskCntl_b,"bin"), indent=4)
    print_detail("""
REGION SPECIFIC.
The channel mask control (ChMaskCntl) field controls the
interpretation of the previously
defined ChMask bit mask.
""")
    print_v("NbTrans", NbTrans_i, formx(NbTrans_b,"bin"), indent=4)
    print_detail("""
The NbTrans field is the number of transmissions for each uplink message.
""")

def parse_maccmd_LinkADRAns(mac_cmd):
    Status_x = mac_cmd[0]
    Status_b = x2bin(Status_x)
    rfu_b = Status_b[0:5]
    Power_ACK_b = Status_b[5]
    Data_rate_ACK_b = Status_b[6]
    Channel_mask_ACK_b = Status_b[7]
    print_v("Status", formx(Status_x), formx(Status_b,"bin"), indent=3)
    print_v("RFU", formx(rfu_b,"bin"), indent=4)
    print_v("Power ACK", Power_ACK_b, indent=4)
    if Power_ACK_b == "0":
        print_detail("""
The device is unable to operate at or below the requested power level.. The
command was discarded and the end-device state was not
changed.
""")
    else:
        print_detail("""
The device is able to operate at or below the requested power level,, or the
TXPower field of the request was set to 15, meaning it
shall be ignored
""")
    print_v("Data_rate_ACK", Data_rate_ACK_b, indent=4)
    if Data_rate_ACK_b == "0":
        print_detail("""
The data rate requested is unknown to the end-device or is
not possible given the channel mask provided (not supported
by any of the enabled channels). The command was discarded
and the end-device state was not changed.
""")
    else:
        print_detail("""
The data rate was successfully set or the DataRate field of
the request was set to 15, meaning it was ignored
""")
    print_v("Channel_mask_ACK", Channel_mask_ACK_b, indent=4)
    if Channel_mask_ACK_b == "0":
        print_detail("""
The channel mask sent enables a yet undefined channel or the channel mask
required all channels to be disabled. The command was
discarded and the end- device state was not changed.
""")
    else:
        print_detail("""
The channel mask sent was successfully interpreted. All currently defined
channel states were set according to the mask.
""")

def parse_maccmd_DutyCycleReq(mac_cmd):
    DutyCyclePL_x = mac_cmd[0:1]
    DutyCyclePL_b = x2bin(DutyCyclePL_x)
    rfu_b = DutyCyclePL_b[0:4]
    MaxDCycle_b = DutyCyclePL_b[4:8]
    duty_cycle = ("No duty cycle" if MaxDCycle_b == "0000" else
                  1./(2**x2int(MaxDCycle_b)))
    print_v("DutyCyclePL", indent=3)
    print_v("RFU", formx(rfu_b,"bin"), indent=4)
    print_v("MaxDCycle", x2bin(DutyCyclePL_x), formx(MaxDCycle_b,"bin"),
            indent=4)
    print_v("Aggregated duty cycle", duty_cycle, indent=4)
    print_detail("""
A value of 0 corresponds to "no duty cycle limitation"
except the one set by the regional regulation.
""")

def parse_maccmd_DutyCycleAns(mac_cmd):
    # zero length
    pass

def parse_maccmd_RXParamSetupReq(mac_cmd):
    DLsettings_x = mac_cmd[0:1]
    Frequency_x = mac_cmd[1:4]
    # DLsettings
    DLsettings_b = x2bin(DLsettings_x)
    rfu_b = DLsettings_b[0:1]
    RX1DRoffset_b = DLsettings_b[1:4]
    RX2DataRate_b = DLsettings_b[4:8]
    RX1DRoffset_i = x2int(RX1DRoffset_b)
    RX2DataRate_i = x2int(RX2DataRate_b)
    print_v("DLsettings", indent=3)
    print_v("RFU", formx(rfu_b,"bin"), indent=4)
    print_v("RX1DRoffset", RX1DRoffset_i, formx(RX1DRoffset_b,"bin"), indent=4)
    print_detail("""
The RX1DRoffset field sets the offset between the uplink data
rate and the downlink data
rate used to communicate with the end-device on the first
reception slot (RX1). As a default
this offset is 0. The offset is used to take into account
maximum power density constraints
for base stations in some regions and to balance the
uplink and downlink radio link margins.
""")
    print_v("RX2DataRate", RX2DataRate_i, forx(RX2DataRate_b,"bin"), indent=4)
    print_detail("""
The RX2DataRate field defines the data rate of a downlink using the second
receive window following the same convention as the
LinkADRReq command (0 means DR0/125kHz for example).
""")
    # Frequency
    parse_macsubcmd_Frequency(Frequency_x)
    print_detail("""
The frequency (Freq) field corresponds to the frequency of
the channel used for the second receive window, whereby
the frequency is coded following
the convention defined in the NewChannelReq command.
""")

def parse_maccmd_RXParamSetupAns(mac_cmd):
    Status_x = mac_cmd[0:1]
    # Status
    Status_b = x2bin(Status_x)
    rfu_b = Status_b[0:5]
    RX1DRoffset_ACK_b = Status_b[5:6]
    RX2Datarate_ACK_b = Status_b[6:7]
    Channel_ACK_b = Status_b[7:8]
    print_v("Status", formx(Status_x), formx(Status_b,"bin"), indent=3)
    print_v("RFU", formx(rfu_b,"bin"), indent=4)
    print_v("RX1DRoffset ACK", formx(RX1DRoffset_ACK_b,"bin"), indent=4)
    if RX1DRoffset_ACK_b == "0":
        print_detail("""
the uplink/downlink data rate offset for RX1 slot is not in the allowed range.
""")
    else:
        print_detail("""
RX1DRoffset was successfully set.
""")
    #
    print_v("RX2 Data rate ACK", formx(RX2Datarate_ACK_b,"bin"), indent=4)
    if RX2Datarate_ACK_b == "0":
        print_detail("""
The data rate requested is unknown to the end-device.
""")
    else:
        print_detail("""
RX2 slot channel was successfully set.
""")
    #
    print_v("Channel ACK", formx(Channel_ACK_b,"bin"), indent=4)
    if Channel_ACK_b == "0":
        print_detail("""
The frequency requested is not usable by the end-device.
""")
    else:
        print_detail("""
RX2 slot channel was successfully set.
""")

def parse_maccmd_DevStatusReq(mac_cmd):
    # zero length
    pass

def parse_maccmd_DevStatusAns(mac_cmd):
    Battery_x = mac_cmd[0:1]
    Margin_x = mac_cmd[1:2]
    # Battery
    Battery_i = x2int(Battery_x)
    print_v("Battery", formx(Battery_i,"pff"), formx(Battery_i), indent=3)
    # Margin
    Status_b = x2bin(Margin_x)
    rfu_b = Status_b[0:2]
    Margin_b = Status_b[2:8]
    Margin_i = int(Margin_b,2) if Margin_b[0] == "0" else ~int(Margin_b,2)+32
    print_v("Margin", formx(Margin_x), formx(Status_b,"bin"), indent=3)
    print_v("RFU", formx(rfu_b,"bin"), indent=4)
    print_v("Margin", Margin_i, formx(Margin_b,"bin"), indent=4)
    print_detail("""
The margin (Margin) is the demodulation signal-to-noise ratio in dB rounded to
the nearest
integer value for the last successfully received
DevStatusReq command. It is a signed
integer of 6 bits with a minimum value of -32 and a
maximum value of 31.
""")

def parse_maccmd_NewChannelReq(mac_cmd):
    ChIndex_x = mac_cmd[0:1]
    ChIndex_i = x2int(ChIndex_x)
    print_v("ChIndex", ChIndex_i, formx(ChIndex_x), indent=3)
    print_detail("""
The channel index (ChIndex) is the index of the channel being created or
modified.
Depending on the region and frequency band used, in
certain regions (cf [PHY]) the LoRaWAN specification imposes default
channels which must be common to all devices and
cannot be modified by the NewChannelReq command.
If the number of default channels is N,
the default channels go from 0 to N-1,
and the acceptable range for ChIndex is N to 15.
A device must be able to handle at least 16 different
channel definitions. In certain region the
device may have to store more than 16 channel definitions.
""")
    parse_macsubcmd_Frequency(mac_cmd[1:4])
    print_detail("""
If the number of default channels is
N, the default channels go from 0 to N-1, and the
acceptable range for ChIndex is N to 15. A
device must be able to handle at least 16 different
channel definitions. In certain region the
device may have to store more than 16 channel definitions.
""")
    #
    DrRange_x = mac_cmd[4:5]
    DrRange_b = x2bin(DrRange_x)
    MaxDR_b = DrRange_b[0:4]
    MaxDR_i = x2int(MaxDR_b)
    MinDR_b = DrRange_b[4:8]
    MinDR_i = x2int(MinDR_b)
    print_v("DrRange", formx(DrRange_x), formx(DrRange_b,"bin"), indent=3)
    print_v("MaxDR", MaxDR_i, formx(MaxDR_b,"bin"), indent=4)
    print_v("MinDR", MinDR_i, formx(MinDR_b,"bin"), indent=4)
    print_detail("""
the minimum data rate (MinDR) subfield
designate the lowest uplink data rate allowed on this channel.
Similarly, the maximum data rate
(MaxDR) designates the highest uplink data rate.
""")

def parse_maccmd_NewChannelAns(mac_cmd):
    Status_x = mac_cmd[0:1]
    Status_b = x2bin(Status_x)
    rfu_b = Status_b[0:6]
    Data_rate_range_ok_b = Status_b[6:7]
    Channel_frequency_ok_b = Status_b[7:8]
    print_v("Status", formx(Status_x), formx(Status_b,"bin"), indent=3)
    print_v("RFU", formx(rfu_b,"bin"), indent=4)
    print_v("Data rate range ok", formx(Data_rate_range_ok_b,"bin"), indent=4)
    if Data_rate_range_ok_b == "0":
        print_detail("""
The designated data rate range exceeds the ones currently defined
for this end-device.
""")
    else:
        print_detail("""
The data rate range is compatible with the possibilities of the end-device.
""")
    print_v("Channel frequency ok", formx(Channel_frequency_ok_b,"bin"),
            indent=4)
    if Channel_frequency_ok_b == "0":
        print_detail("""
The device cannot use this frequency.
""")
    else:
        print_detail("""
The device is able to use this frequency.
""")

def parse_maccmd_RXTimingSetupReq(mac_cmd):
    Settings_x = mac_cmd[0:1]
    Settings_b = x2bin(Settings_x)
    rfu_b = Settings_b[0:4]
    Del_b = Settings_b[4:8]
    Del_i = 1 if Del_b == "0" else int(Del_b,2)
    print_v("Settings", formx(Settings_x), formx(Settings_b,"bin"), indent=3)
    print_v("RFU", formx(rfu_b,"bin"), indent=4)
    print_v("Delay", "{} sec".format(Del_i), formx(Del_b,"bin"), indent=4)
    print_detail("""
The delay (Delay) field specifies the delay in second.
the value of 0 and 1 indicates 1 (s).
the value of 15 indicates 15 (s).
""")

def parse_maccmd_RXTimingSetupAns(mac_cmd):
    # zero length
    pass

def parse_maccmd_TxParamSetupReq(mac_cmd):
    DwellTime_x = mac_cmd[0:1]
    DwellTime_b = x2bin(DwellTime_x)
    rfu_b = DwellTime_b[0:2]
    DownlinkDwellTime_b = DwellTime_b[2:3]
    UplinkDwellTime_b = DwellTime_b[3:4]
    MaxEIRP_b = DwellTime_b[4:8]
    MaxEIRP_i = [8,10,12,13,14,16,18,20,
                 21,24,26,27,29,30,33,36][x2int(MaxEIRP_b)]
    print_v("DwellTime", formx(DwellTime_x), indent=3)
    print_v("RFU", formx(rfu_b,"bin"), indent=4)
    print_v("DownlinkDwellTime", parse_macsubcmd_dwelltime(DownlinkDwellTime_b),
            formx(DownlinkDwellTime_b,"bin"), indent=4)
    print_v("UplinkDwellTime", parse_macsubcmd_dwelltime(UplinkDwellTime_b),
            formx(UplinkDwellTime_b,"bin"), indent=4)
    print_v("MaxEIRP", MaxEIRP_i, formx(MaxEIRP_b,"bin"), indent=4)

def parse_maccmd_TxParamSetupAns(mac_cmd):
    # zero length
    pass

def parse_maccmd_DlChannelReq(mac_cmd):
    ChIndex_x = mac_cmd[0:1]
    print_detail("""
The channel index (ChIndex) is the index of the
channel whose downlink frequency is
modified.
""")
    parse_macsubcmd_Frequency(mac_cmd[1:4])

def parse_maccmd_DlChannelAns(mac_cmd):
    Status_x = mac_cmd[0:1]
    Status_b = x2bin(Status_x)
    rfu_b = Status_b[0:6]
    Uplink_frequency_exists_b = Status_b[6:7]
    Channel_frequency_ok_b = Status_b[7:8]
    print_v("Status", formx(Status_x), formx(Status_b,"bin"), indent=3)
    print_v("RFU", formx(rfu_b,"bin"), indent=4)
    print_v("Uplink frequency exists", formx(Uplink_frequency_exists_b,"bin"),
            indent=4)
    if Uplink_frequency_exists_b == "0":
        print_detail("""
The uplink frequency is not defined for this channel, the downlink frequency
can only be set for a channel that already has
a valid uplink frequency
""")
    else:
        print_detail("""
The uplink frequency of the channel is valid.
""")
    print_v("Channel frequency ok", formx(Channel_frequency_ok_b,"bin"),
            indent=4)
    if Channel_frequency_ok_b == "0":
        print_detail("""
The device cannot use this frequency.
""")
    else:
        print_detail("""
The device is able to use this frequency.
""")

#
# Class B Mac Command Parsers
#
def parse_maccmd_PingSlotInfoReq(mac_cmd):
    PingSlotParam_x = mac_cmd[0]
    PingSlotParam_b = x2bin(PingSlotParam_x)
    rfu_b = PingSlotParam_b[0:5]
    Periodicity_b = PingSlotParam_b[5:8]
    Periodicity_i = int(Periodicity_b,2)
    print_v("PingSlotParam", formx(PingSlotParam_x), indent=3)
    print_v("RFU", formx(rfu_b,"bin"), indent=4)
    print_v("Periodicity", Periodicity_i, formx(Periodicity_b,"bin"), indent=4)
    print_v("pingSlotPeriod", formx(2**Periodicity_i,"sec"), indent=5)
    print_detail("""
Periodicity = 0 means that the end-device opens a ping slot every second.
Periodicity = 7, every 128 seconds which is the maximum ping period
supported by the LoRaWAN Class B specification.
""")

def parse_maccmd_PingSlotInfoAns(mac_cmd):
    # zero length
    pass

def parse_maccmd_PingSlotChannelReq(mac_cmd):
    parse_macsubcmd_Frequency(mac_cmd[0:3])
    DR_x = mac_cmd[3:4]
    DR_b = x2bin(DR_x)
    rfu_b = DR_b[0:4]
    datarate_b = DR_b[4:8]
    datarate_i = int(datarate_i, 2)
    print_v("DataRate", formx(DR_x), indent=3)
    print_v("RFU", formx(rfu_b,"bin"), indent=4)
    print_v("data rate", datarate_i, formx(datarate_b,"bin"), indent=4)
    print_detail("""
The “data rate” subfield is the index of the Data Rate used
for the ping-slot downlinks.
""")

def parse_maccmd_PingSlotChannelAns(mac_cmd):
    Status_x = mac_cmd[0:1]
    Status_b = x2bin(Status_x)
    rfu_b = Status_b[0:6]
    datarate_ok_b = Status_b[6:7]
    chfreq_ok_b = Status_b[7:8]
    print_v("Status", formx(Status_b,"bin"), formx(Status_x), indent=3)
    print_v("RFU", formx(rfu_b,"bin"), indent=4)
    print_v("data rate ok", formx(datarate_ok_b,"bin"), indent=4)
    print_v("ch freq ok", formx(chfreq_ok_b,"bin"), indent=4)
    print_detail("""
for data rate ok,
if 0, Data rate ok: The designated data rate is not defined for this end device,
the previous data rate is kept.
if 1, The data rate is compatible with the possibilities of the end device
The device cannot receiveon this frequency
This frequency can be used by the end-device
If either of those 2 bits equals 0, the command did not succeed and the
ping-slot parameters have not been modified.
""")

def parse_maccmd_BeaconTimingReq(mac_cmd):
    print_detail("""
DEPRECATED.
The network may answer only a limited number of requests per a given time
period.  An end-device must not expect that BeaconTimingReq is answered
immediately with a BeaconTimingAns. Class A end-devices wanting to switch
to Class B should not transmit more than one BeaconTimingReq per hour.
""")

def parse_maccmd_BeaconTimingAns(mac_cmd):
    print_detail("""
DEPRECATED.
""")
    Delay_x = mac_cmd[0:2]
    Delay_i = x2int(Delay_x)
    print_v("Delay", Delay_i, formx(Delay_x), indent=3)
    print_detail("""
If the remaining time between the end of the
current downlink frame and the start of the next beacon frame is noted RTime
then: 30 ms x (Delay+1) > RTime >= 30 ms x Delay
""")
    Channel_x = mac_cmd[2:3] 
    Channel_i = int(Channel_x, 16)
    print_v("Channel", Channel_i, formx(Channel_x), indent=3)
    print_detail("""
In networks where the beacon uses alternatively several channels,
the "Channel" field is the index of the beaconing channel
on which the next beacon will be broadcasted.
For networks where the beacon broadcast frequency is fixed then this field
content is 0.
""")

def parse_maccmd_BeaconFreqReq(mac_cmd):
    print_detail("""
to modify the frequency on which this 2181 end-device expects the beacon.
""")
    Frequency_x = mac_cmd[0:3]
    Frequency_i = x2int(Frequency_x)
    print_v("Frequency:", formx(Frequency_i, "hz"), formx(Frequency_x),
            indent=3)
    print_detail("""
Frequency is a 24bits unsigned integer. The actual beacon
channel frequency in Hz is 100 x frequ. This allows defining
the beacon channel anywhere between 100 MHz to 1.67 GHz
by 100 Hz step. The end-device has to check that the frequency
is actually allowed by its radio hardware and return an error otherwise.
A valid non-zero Frequency will force the device to listen
to the beacon on a fixed frequency channel even if the default
behavior specifies a frequency hopping beacon (i.e US ISM band).
A value of 0 instructs the end-device to use the default
beacon frequency plan as defined in the "Beacon physical layer" section.
Where applicable the device resumes frequency hopping beacon search.
""")

def parse_maccmd_BeaconFreqAns(mac_cmd):
    print_detail("""
answer to modification the frequency on which this end-device expects the beacon.
""")
    Status_x = mac_cmd[0:1]
    Status_b = x2bin(Status_x)
    rfu_b = Status_b[0:6]
    ok_b = Status_b[7:8]
    print_v("Status:", formx(Status_x), formx(Status_b,"bin"), indent=3)
    print_v("RFU:", formx(rfu_b,"bin"), indent=4)
    print_v("Beacon frequency ok:", ok_b, formx(ok_b,"bin"), indent=4)
    print_detail("""
Bit=0: The device cannot use this frequency, the previous beacon frequency is
kept.
Bit=1: The beacon frequency has been changed
""")

#
# Class C Mac Command Parsers
#
def parse_maccmd_DeviceModeInd(mac_cmd):
    parse_macsubcmd_DeviceMode_class(mac_cmd[0])

def parse_maccmd_DeviceModeConf(mac_cmd):
    parse_macsubcmd_DeviceMode_class(mac_cmd[0])

"""
Table for MAC Command Parser
    name: MAC command name
    size: command size in octet.
    parser: function name.
"""
mac_cmd_tab = {
    # Class A Mac Command
    0x01: {
        MSGDIR_UP: {
            "name": "ResetInd",
            "size": 1,
            "parser": parse_maccmd_ResetInd
        },
        MSGDIR_DOWN: {
            "name": "ResetConf",
            "size": 1,
            "parser": parse_maccmd_ResetConf
        }
    },
    0x02: {
        MSGDIR_UP: {
            "name": "LinkCheckReq",
            "size": 0,
            "parser": parse_maccmd_LinkCheckReq
        },
        MSGDIR_DOWN: {
            "name": "LinkCheckAns",
            "size": 2,
            "parser": parse_maccmd_LinkCheckAns
        }
    },
    0x03: {
        MSGDIR_UP: {
            "name": "LinkADRAns",
            "size": 1,
            "parser": parse_maccmd_LinkADRAns
        },
        MSGDIR_DOWN: {
            "name": "LinkADRReq",
            "size": 4,
            "parser": parse_maccmd_LinkADRReq
        }
    },
    0x04: {
        MSGDIR_UP: {
            "name": "DutyCycleAns",
            "size": 0,
            "parser": parse_maccmd_DutyCycleAns
        },
        MSGDIR_DOWN: {
            "name": "DutyCycleReq",
            "size": 1,
            "parser": parse_maccmd_DutyCycleReq
        }
    },
    0x05: {
        MSGDIR_UP: {
            "name": "RXParamSetupAns",
            "size": 1,
            "parser": parse_maccmd_RXParamSetupAns
        },
        MSGDIR_DOWN: {
            "name": "RXParamSetupReq",
            "size": 4,
            "parser": parse_maccmd_RXParamSetupReq
        }
    },
    0x06: {
        MSGDIR_UP: {
            "name": "DevStatusAns",
            "size": 2,
            "parser": parse_maccmd_DevStatusAns
        },
        MSGDIR_DOWN: {
            "name": "DevStatusReq",
            "size": 0,
            "parser": parse_maccmd_DevStatusReq
        }
    },
    0x07: {
        MSGDIR_UP: {
            "name": "NewChannelAns",
            "size": 1,
            "parser": parse_maccmd_NewChannelAns
        },
        MSGDIR_DOWN: {
            "name": "NewChannelReq",
            "size": 5,
            "parser": parse_maccmd_NewChannelReq
        }
    },
    0x08: {
        MSGDIR_UP: {
            "name": "RXTimingSetupAns",
            "size": 0,
            "parser": parse_maccmd_RXTimingSetupAns
        },
        MSGDIR_DOWN: {
            "name": "RXTimingSetupReq",
            "size": 1,
            "parser": parse_maccmd_RXTimingSetupReq
        }
    },
    0x09: {
        MSGDIR_UP: {
            "name": "TxParamSetupAns",
            "size": 0,
            "parser": parse_maccmd_TxParamSetupAns
        },
        MSGDIR_DOWN: {
            "name": "TxParamSetupReq",
            "size": 1,
            "parser": parse_maccmd_TxParamSetupReq
        }
    },
    0x0a: {
        MSGDIR_UP: {
            "name": "DlChannelAns",
            "size": 1,
            "parser": parse_maccmd_DlChannelAns
        },
        MSGDIR_DOWN: {
            "name": "DlChannelReq",
            "size": 4,
            "parser": parse_maccmd_DlChannelReq
        }
    },
    # Class B Mac Command
    0x10: {
        MSGDIR_UP: {
            "name": "PingSlotInfoReq",
            "size": 1,
            "parser": parse_maccmd_PingSlotInfoReq
        },
        MSGDIR_DOWN: {
            "name": "PingSlotInfoAns",
            "size": 0,
            "parser": parse_maccmd_PingSlotInfoAns
        }
    },
    0x11: {
        MSGDIR_UP: {
            "name": "PingSlotChannelAns",
            "size": 4,
            "parser": parse_maccmd_PingSlotChannelAns
        },
        MSGDIR_DOWN: {
            "name": "PingSlotChannelReq",
            "size": 4,
            "parser": parse_maccmd_PingSlotChannelReq
        }
    },
    0x12: {
        MSGDIR_UP: {
            "name": "BeaconTimingReq",
            "size": 0,
            "parser": parse_maccmd_BeaconTimingReq
        },
        MSGDIR_DOWN: {
            "name": "BeaconTimingAns",
            "size": 3,
            "parser": parse_maccmd_BeaconTimingAns
        }
    },
    0x13: {
        MSGDIR_UP: {
            "name": "BeaconFreqAns",
            "size": 1,
            "parser": parse_maccmd_BeaconFreqAns
        },
        MSGDIR_DOWN: {
            "name": "BeaconFreqReq",
            "size": 3,
            "parser": parse_maccmd_BeaconFreqReq
        }
    },
    # Class C Mac Command
    0x20: {
        MSGDIR_UP: {
            "name": "DeviceModeInd",
            "size": 1,
            "parser": parse_maccmd_DeviceModeInd
        },
        MSGDIR_DOWN: {
            "name": "DeviceModeConf",
            "size": 1,
            "parser": parse_maccmd_DeviceModeConf
        }
    }
    }

def parse_mac_cmd(mac_cmds, msg_dir, version):
    offset = 0
    n_cmd = 0
    dir_str = "Up" if msg_dir == 0 else "Down"
    if opt.verbose:
        print_vt("MAC Command (No. CMD CID DIR [MSG])")
    else:
        print_vt("MAC Command (No. CMD CID DIR)")
    while offset < len(mac_cmds):
        cid = mac_cmds[offset]
        a = mac_cmd_tab.get(cid)
        if a is not None:
            t = mac_cmd_tab[cid][msg_dir]
            offset += 1
            n_cmd += 1
            cmd = mac_cmds[offset:1+offset+t["size"]]
            if t["size"] == 0:
                print_v("{}. {}".format(n_cmd,t["name"]),
                        "0x{:02x} {}link".format(cid,dir_str), indent=2)
            else:
                print_v("{}. {}".format(n_cmd,t["name"]),
                        "0x{:02x} {}link".format(cid,dir_str), formx(cmd),
                        indent=2)
            # call a parser for a mac command.
            t["parser"](cmd)
            offset += t["size"]
        else:
            print_w("looks a proprietary MAC command #{}.".format(
                    mac_cmds[offset]))
            # just stop to parse all.
            return

def parse_fhdr(payload, msg_dir, version, upper_fcnt=b"\x00\x00"):
    """
    FHDR Parser.
    - payload: mac payload (MHDR is not included) in bytes.
    - FHDR format is:
           4    |   1   |   2  | 0...15
        DevAddr | FCtrl | FCnt | FOpts
    """
    devaddr = payload[0:4][::-1]
    fctrl_x = payload[4:5]
    fcnt_x = payload[5:7][::-1]
    """
    FCtrl
        - FCtrl for downlink
                     7  |     6     |  5  |    4     |   3...0
            v1.0    ADR | ADRACKReq | ACK | FPending | FOptsLen
            v1.0.3  ADR |    RFU    | ACK | FPending | FOptsLen
        - FCtrl for uplink
                     7  |    6      |  5  |    4     |   3...0
            v1.0    ADR | ADRACKReq | ACK |   RFU    | FOptsLen
            v1.0.3  ADR | ADRACKReq | ACK |  ClassB  | FOptsLen
    """
    fctrl_b = x2bin(fctrl_x)
    foptslen_b = fctrl_b[4:]
    foptslen_i = int(foptslen_b,2)
    #
    print_v("FHDR", formx(payload[0:7+foptslen_i]))
    print_v("DevAddr", formx(devaddr), formx(devaddr[::-1]), indent=2)
    print_v("FCtrl", formx(fctrl_x), formx(fctrl_b,"bin"), indent=2)
    #
    if msg_dir == MSGDIR_DOWN:
        adr_b = fctrl_b[0]
        adrackreq_rfu_b = fctrl_b[1]
        ack_b = fctrl_b[2]
        fpending_b = fctrl_b[3]
        #
        print_v("ADR", formx(adr_b,"bin"), indent=3)
        if version != "1.0":
            print_v("ADRACKReq", formx(adrackreq_rfu_b,"bin"), indent=3)
        else:
            print_v("RFU", formx(adrackreq_rfu_b,"bin"), indent=3)
        print_v("ACK", formx(ack_b,"bin"), indent=3)
        print_v("FPending", formx(fpending_b,"bin"), indent=3)
        print_v("FOptsLen", foptslen_i, formx(foptslen_b,"bin"), indent=3)
        fctrl_o = {
                "fctrl_bits": fctrl_b,
                "adr": int(adr_b),
                "ack": int(ack_b),
                "fpending": int(fpending_b),
                "foptslen": foptslen_i
                }
    else:
        adr_b = fctrl_b[0]
        adrackreq_b = fctrl_b[1]
        ack_b = fctrl_b[2]
        classb_b = fctrl_b[3]
        #
        print_v("ADR", formx(adr_b,"bin"), indent=3)
        print_v("ADRACKReq", formx(adrackreq_b,"bin"), indent=3)
        print_v("ACK", formx(ack_b,"bin"), indent=3)
        if version != "1.0":
            print_v("RFU", formx(classb_b,"bin"), indent=3)
        else:
            print_v("ClassB", formx(classb_b,"bin"), indent=3)
        print_v("FOptsLen", foptslen_i, formx(foptslen_b,"bin"), indent=3)
        fctrl_o = {
                "fctrl_bits": fctrl_b,
                "adr": int(adr_b),
                "adrackreq": int(adrackreq_b),
                "ack": int(ack_b),
                "classb": int(classb_b),
                "foptslen": foptslen_i
                }
    #
    fcnt_i = x2int(fcnt_x[::-1]+upper_fcnt[::-1])
    print_v("FCnt", fcnt_i, formx(upper_fcnt+fcnt_x), indent=2)
    if foptslen_i == 0:
        fopts_o = None
        fhdr_size = 7
    else:
        # foptslen_i > 0
        fhdr_size = 7 + foptslen_i
        mac_cmds = payload[7:fhdr_size]
        print_v("FOpts", formx(mac_cmds), indent=2)
        fopts_o = parse_mac_cmd(mac_cmds, msg_dir, version)
    #
    return {
            "devaddr": devaddr,
            "fctrl": fctrl_o,
            "fcnt": upper_fcnt+fcnt_x,
            "fopts": fopts_o,
            "fhdr_size": fhdr_size,
            }

def parse_mac_payload(phy_pdu, mhdr_o, nwkskey=None, appskey=None,
                      version="1.0.3", upper_fcnt=b"\x00\x00"):
    """
    MACPayload parser
    - phy_pdu: in bytearray.
    - MACPayload
        FHDR | FPort | FRMPayload
        or
        FHDR
    """
    # set msg_dir
    if mhdr_o["mtype"] in [ "000", "010", "100" ]:
        msg_dir = MSGDIR_UP
    elif mhdr_o["mtype"] in [ "001", "011", "101" ]:
        msg_dir = MSGDIR_DOWN
    else:
        print_w("unknown msg direction")
        return { "msg_dir": MSGDIR_UNKNOWN }
    """
## FOptsLen, FOpts, FPort, FRMPayload

- v1.0, v1.0.3

4.3.1.6 Frame options (FOptsLen in FCtrl, FOpts)
If FOptsLen is 0, the FOpts field is absent.
If FOptsLen is different from 0,
i.e. if MAC commands are present in the FOpts field, the port 0 cannot be used
(FPort must be either not present or different from 0).

MAC commands cannot be simultaneously present in the payload field
and the frame options field.

4.3.2 Port field (FPort)
If the frame payload field is not empty, the port field must be present
If present, an FPort value of 0 indicates that the FRMPayload contains
MAC commands

5 MAC Commands
A single data frame can contain any sequence of MAC commands,
either piggybacked in the FOpts field or, when sent as a separate data frame,
in the FRMPayload field with the FPort field being set to 0.
Piggybacked MAC commands are always sent without encryption and
must not exceed 15 octets. MAC commands sent as FRMPayload are always
encrypted and must not exceed the maximum FRMPayload length.

## Possible frame format

       <-------------- FHDR ------------->
       DevAddr | FCtrl     | FCnt | FOpts | FPort | FRMPayload
       ========+===========+======+=======+=======+=============
    1) DevAddr | foptlen=0 | FCnt | (nul) | != 0  | App. message
    2) DevAddr | foptlen=0 | FCnt | (nul) |  = 0  | MAC Commands
    3) DevAddr | foptlen>0 | FCnt | FOpts | (nul) | (nul)
    4) DevAddr | foptlen>0 | FCnt | FOpts | != 0  | App. message
    """
    payload = phy_pdu[1:-__MIC_SIZE]
    fhdr_o = parse_fhdr(payload, msg_dir, version)
    # base object to be returned.
    ret_o = {
            "devaddr": fhdr_o["devaddr"],
            "fctrl": fhdr_o["fctrl"],
            "fcnt": fhdr_o["fcnt"],
            "fopts": fhdr_o["fopts"],
            "fhdr_size": fhdr_o["fhdr_size"],
            }
    # MIC calculation
    if nwkskey is not None:
        # mic_target is MHDR | FHDR | FPort | FRMPayload
        mic_target = phy_pdu[0:-__MIC_SIZE]
        print_d("NwkSKey", formx(nwkskey))
        print_d("Data", formx(mic_target))
        print_d("Data length", "{}".format(len(mic_target)))
        print_d("DevAddr", formx(fhdr_o["devaddr"]))
        print_d("Direction", msg_dir)
        print_d("FCnt", formx(fhdr_o["fcnt"]))
        mic_derived = lorawan_frmp_integrity(nwkskey, mic_target,
                                             devaddr=fhdr_o["devaddr"],
                                             msg_dir=msg_dir,
                                             fcnt=fhdr_o["fcnt"])
        ret_o.update({"mic_derived": mic_derived["mic"]})
        print_d("CMAC", formx(mic_derived["cmac"]))
        print_d("MIC", formx(mic_derived["mic"]))
    else:
        print_w("not checked MIC due to no NwkSKey specified.")
        mic_derived = None
    #
    offset = fhdr_o["fhdr_size"]
    rest_size = len(payload) - offset
    if rest_size < 0:
        print_w("invalid fhdr_size={}, rest_size={}".format(fhdr_o["fhdr_size"],
                                                            rest_size))
        return ret_o
    if rest_size == 0:
        # case 3
        return ret_o
    # case 1,2,4
    fport = payload[offset:offset+1]
    fport_i = fport[0]
    print_v("FPort", fport_i, formx(fport), indent=2)
    ret_o.update({ "fport": fport_i })
    #
    offset += 1
    rest_size -= 1
    payload = payload[offset:]
    if rest_size <= 0:
        print_w("payload size is too short. rest_size={}".format(rest_size))
        return ret_o
    # decrypting
    if fport_i == 0:
        # case 2
        print_vt("FRMPayload(MAC Command)", formx(payload))
        if fhdr_o["fctrl"]["foptslen"] > 0:
            print_w("MAC Commands exist in both FOpts and FRMPayload.")
            # thru
        if nwkskey is not None:
            print_d("NwkSKey", formx(nwkskey))
            print_d("Data", formx(payload))
            print_d("Data length", "{}".format(len(payload)))
            print_d("DevAddr", formx(fhdr_o["devaddr"]))
            print_d("Direction", msg_dir)
            print_d("FCnt", formx(fhdr_o["fcnt"]))
            payload = lorawan_frmp_encryption(nwkskey, payload,
                                              devaddr=fhdr_o["devaddr"],
                                              msg_dir=msg_dir,
                                              fcnt=fhdr_o["fcnt"])
            ret_o.update({ "payload": payload })
            print_d("Decrypted", formx(payload))
            print_v("MAC Commands", formx(payload))
            frm_o = parse_mac_cmd(payload, msg_dir, version)
            ret_o.update({ "frm_mac": frm_o })
        else:
            print_w("not decrypted MAC Command due to no NwkSKey specified.")
        #
        return ret_o
    else:
        # case 1,4
        if fport_i == 224:
            print_vt("FRMPayload (MAC Command Test)", formx(payload))
        else:
            print_vt("FRMPayload (Application Data)", formx(payload))
        #
        if appskey is not None:
            print_d("AppSKey", formx(appskey))
            print_d("Data", formx(payload))
            print_d("Data length", "{}".format(len(payload)))
            print_d("DevAddr", formx(fhdr_o["devaddr"]))
            print_d("Direction", msg_dir)
            print_d("FCnt", formx(fhdr_o["fcnt"]))
            payload = lorawan_frmp_encryption(appskey, payload,
                                              devaddr=fhdr_o["devaddr"],
                                              msg_dir=msg_dir,
                                              fcnt=fhdr_o["fcnt"])
            ret_o.update({ "payload": payload })
            print_d("Decrypted", formx(payload))
            #
            if fport_i == 224:
                print_v("TestData", formx(payload))
            else:
                print_v("AppData", formx(payload))
        else:
            print_w("not decrypt Application Data due to no AppSKey specified.")
        #
        return ret_o

def parse_netid(netid_x):
    """
    NetID parser.
        netid: 3 bytes in host order.
    """
    print_v("NetID", formx(netid_x), formx(netid_x[::-1]))
    netid_b = x2bin(netid_x)
    nwkid_b = netid_b[0:7]
    print_v("NwkID", formx(nwkid_b,"bin"), indent=2)
    return {
            "netid": netid_x,
            "nwkid": nwkid_b,
            "residue": netid_b[7:]
            }

def parse_dlsettings(dlsets):
    """
    DLSettings parser.
        dlsets: 1 bytes int.
            RFU: 1 bits
            RX1DRoffset: 3 b
            RX2DataRate: 4 b
    """
    dlsets_b = x2bin(dlsets)
    rfu_b = dlsets_b[0]
    dlsets_rx1do_b = dlsets_b[1:4]
    dlsets_rx1do_i = int(dlsets_b[1:4], 2)
    dlsets_rx2dr_b = dlsets_b[4:]
    dlsets_rx2dr_i = int(dlsets_b[4:], 2)
    #
    print_v("DLSettings", formx(dlsets), formx(dlsets_b,"bin"))
    print_v("RFU", formx(rfu_b,"bin"), indent=2)
    print_v("RX1DROffset", dlsets_rx1do_i, formx(dlsets_rx1do_b,"bin"),
            indent=2)
    print_v("RX2DataRate", dlsets_rx2dr_i, formx(dlsets_rx2dr_b,"bin"),
            indent=2)
    #
    return {
            "dlsettings": dlsets,
            "rx1droffset": dlsets_rx1do_i,
            "rx2datarate": dlsets_rx2dr_i,
            }

def parse_cflist(cflist_x, region):
    if region == "AS923":
        nb_start = 2 # AS923
    elif region == "EU868":
        nb_start = 3 # EU868
    elif region == "US920":
        nb_start = 0 # US920
        raise NotImplementedError("CFList of US920 is not implemented yet.")
    else:
        raise NotImplementedError("CFList of xxx is not implemented yet.")
    #
    print_v("CFList", formx(cflist_x))
    cflist = []
    for i in range(5):
        cf = cflist_x[i*3:i*3+3]
        cf_i = x2int(cf)
        cflist.append(cf_i)
        print_v("CF{}".format(nb_start+i), formx(cf_i,"hz"), formx(cf),
                indent=2)
    print_v("CFListType", cflist_x[-1], formx(cflist_x[-2:-1]), indent=2)
    return {
            "cflist": cflist,
            "cflisttype": cflist_x[-1]
            }

def parse_join_accept(phy_pdu, appkey=None, version="1.0.3", region="AS923"):
    """
    JoinAccept parser
    - phy_pdu is MHDR + Join-Accept + MIC in bytearray.
    - The format of Join-Accept is:
        + v1.0.3
            3    |   3   |    4    |     1      |    1    |  (16)
        AppNonce | NetID | DevAddr | DLSettings | RxDelay | (CFList)
        + v1.0
            3    |   3   |    4    |     1      |    1    |  (16)
        AppNonce | NetID | DevAddr |    RFU     | RxDelay | (CFList)
    - And, the MIC is calculated by:
        aes128_cmac(AppKey, MHDR | Join-Accept)
    - At the server, Join-Accept + MIC are encrypted by:
        aes128_decrypt(AppKey, Join-Accept | MIC)
    """
    if len(phy_pdu) not in [17,33]:
        print_w("length of PHY PDU of Join Accept must be 17 or 33, but {}".format(len(phy_pdu)))
    payload = phy_pdu[1:]
    if appkey is not None:
        # See the section of Join Accept message.
        # LoRaWN network server uses aes128_decrypt to encrypt the response.
        # So, here, it's correct to use lorawan_encrypt().
        print_d("Appkey", formx(appkey))
        print_d("Data", formx(payload))
        print_d("Data length", "{}".format(len(payload)))
        payload = lorawan_aes128_encrypt(appkey, payload)
        print_d("Decrypted", formx(payload))
    else:
        print_w("not decrypt Join Accept due to no AppKey specified.")
        return {}
    #
    appnonce_x = payload[0:3][::-1]
    netid_x = payload[3:6][::-1]
    devaddr = payload[6:10][::-1]
    dlsettings_x = payload[10:11]
    rxdelay_x = payload[11:12]
    mic_explicit = payload[-__MIC_SIZE:][::-1]
    #
    print_v("AppNonce", formx(appnonce_x), formx(appnonce_x[::-1]))
    netid_o = parse_netid(netid_x)
    print_v("DevAddr", formx(devaddr), formx(devaddr[::-1]))
    if version != "1.0":
        dlsets_o = parse_dlsettings(dlsettings_x[0])
    else:
        print_v("RFU", formx(dlsettings_x), formx(dlsettings_x))
    rxdelay_i = 1 if rxdelay_x[0] == 0 else rxdelay_x[0]
    print_v("RxDelay", "{} sec".format(rxdelay_i), formx(rxdelay_x))
    # base object to be returned.
    ret_o = {
            "appnonce": appnonce_x,
            "netid": netid_o["netid"],
            "nwkid": netid_o["nwkid"],
            "devaddr": devaddr,
            "dlsettings": dlsets_o["dlsettings"],
            "rx1droffset": dlsets_o["rx1droffset"],
            "rx2datarate": dlsets_o["rx2datarate"],
            "rxdelay": rxdelay_i,
            "mic_explicit": mic_explicit,
            }
    # parse cflist if needed.
    if len(phy_pdu) == 33:
        cflist_o = parse_cflist(payload[12:28], region)
        ret_o.update({"cflist": cflist_o})
    # MIC calculation
    if appkey is not None:
        buf = phy_pdu[0:1] + payload[:-__MIC_SIZE]
        print_d("Appkey", formx(appkey))
        print_d("Msg", formx(buf))
        mic_o = lorawan_aes128_cmac(appkey, buf)
        print_d("CMAC", formx(mic_o["cmac"]))
        ret_o.update({"mic_derived": mic_o["mic"]})
    else:
        print_w("not calculated MIC due to no AppKey specified.")
    #
    return ret_o

def parse_join_request(phy_pdu, appkey=None):
    """
    Join Request parser
        The main part of the request is like below:
          8    |   8    |    2
        AppEUI | DevEUI | DevNonce
    """
    if len(phy_pdu) != 23:
        print_w("length of PHY PDU of Join Request must be 23, but {}".format(len(phy_pdu)))
    payload = phy_pdu[1:]
    appeui_x = payload[0:8][::-1]
    deveui_x = payload[8:16][::-1]
    devnonce_x = payload[16:18][::-1]
    #
    print_v("AppEUI", formx(appeui_x), formx(appeui_x[::-1]))
    print_v("DevEUI", formx(deveui_x), formx(deveui_x[::-1]))
    print_v("DevNonce", formx(devnonce_x), formx(devnonce_x[::-1]))
    # base object to be returned.
    ret_o = {
            "appeui": appeui_x,
            "deveui": deveui_x,
            "devnonce": devnonce_x,
            }
    # MIC calculation
    if appkey is not None:
        buf = phy_pdu[:-__MIC_SIZE]
        print_d("Appkey", formx(appkey))
        print_d("Msg", formx(buf))
        mic_o = lorawan_aes128_cmac(appkey, buf)
        print_d("CMAC", formx(mic_o["cmac"]))
        ret_o.update({"mic_derived": mic_o["mic"]})
    else:
        print_w("not calculated MIC due to no AppKey specified.")
    #
    return ret_o

def parse_mhdr(mhdr):
    """
    MHDR parser
        mhdr: 1 byte.
            7 6 5 | 4 3 2 |  1 0
            MType |  RFU  | Major
    """
    # MHDR parser.
    def get_mtype_cmd(mtype):
        return {
            "000": "Join Request",
            "001": "Join Accept",
            "010": "Unconfirmed Data Up",
            "011": "Unconfirmed Data Down",
            "100": "Confirmed Data Up",
            "101": "Confirmed Data Down",
            "110": "RFU",
            "111": "Proprietary"
            }[mtype]
    #
    def get_major(major):
        return {
            "00": "LoRaWAN R1",
            "01": "RFU",
            "10": "RFU",
            "11": "RFU"
            }[major]
    #
    mhdr_b = x2bin(mhdr)
    mtype_b = mhdr_b[0:3]
    mtype_cmd = get_mtype_cmd(mtype_b)
    rfu_b = mhdr_b[3:6]
    major_b = mhdr_b[6:]
    #
    print_vt("MHDR", formx(mhdr), formx(mhdr_b,"bin"))
    print_v("MType", get_mtype_cmd(mtype_b), formx(mtype_b,"bin"))
    print_v("RFU", formx(rfu_b,"bin"))
    print_v("Major", get_major(major_b), formx(major_b,"bin"))
    #
    return {
            "mhdr_bits": mhdr_b,
            "mtype": mtype_b,
            "mtype_cmd": mtype_cmd,
            "major": major_b,
            }

def parse_phy_pdu(phy_pdu, nwkskey=None, appskey=None, appkey=None,
                  version="1.0.3", upper_fcnt=b"\x00\x00",
                  parse_only=False, option=None):
    """
    PHYPayload parser
        all arguments are in bytearray.
        the format is like below:
              1  |    1...M   |  4
            MHDR | MACPayload | MIC
            MHDR |   JoinReq  | MIC
            MHDR |   JoinRes  | MIC
    """
    if not phy_pdu:
        raise ValueError("phy_pdu must need more than 1 bytes.")
    # set the flag whether to display values or not.
    global __parse_only
    __parse_only = parse_only
    # set opt.
    if option is not None:
        global opt
        opt = option
    #
    if parse_only is False:
        print("=== PHYPayload ===")
    if opt.verbose:
        print_v("PDU", formx(phy_pdu))

    mhdr_o = parse_mhdr(phy_pdu[0])
    payload = phy_pdu[1:-__MIC_SIZE]
    # parse each type of message.
    if mhdr_o["mtype"] == "000":
        print_vt("JoinReq", formx(payload))
        msg_o = parse_join_request(phy_pdu, appkey=appkey)
        mic_x = phy_pdu[-__MIC_SIZE:][::-1]
    elif mhdr_o["mtype"] == "001":
        print_vt("JoinAccept", formx(payload))
        msg_o = parse_join_accept(phy_pdu, appkey=appkey, version=version)
        if "mic_explicit" in msg_o:
            mic_x = msg_o["mic_explicit"]
        else:
            mic_x = None
    elif mhdr_o["mtype"] in [ "011", "101", "010", "100" ]:
        print_vt("MACPayload", formx(payload))
        msg_o = parse_mac_payload(phy_pdu, mhdr_o,
                                  nwkskey=nwkskey, appskey=appskey,
                                  version=version, upper_fcnt=upper_fcnt)
        mic_x = phy_pdu[-__MIC_SIZE:][::-1]
    else:
        print_vt("Proprietary", formx(payload))
        msg_o = { "msg": "proprietary" }
        mic_x = phy_pdu[-__MIC_SIZE:][::-1]
    # base object to be returned.
    ret_o = {
            "mhdr": mhdr_o,
            "body": msg_o,
            }
    print_vt("MIC")
    if mic_x is not None:
        print_v("MIC in frame", formx(mic_x), formx(mic_x[::-1]))
        ret_o.update({"mic": mic_x})
    else:
        # this is only case when the join response hasn't been decoded.
        pass
    if "mic_derived" in msg_o:
        print_v("MIC Derived ", formx(msg_o["mic_derived"]))
    #
    return ret_o

LoRaWAN PHY Payload Parser
==========================

This is a parser tool of the LoRaWAN PHY payload.

DON'T USE [lorawan_phy_parser](https://github.com/tanupoo/lorawan_phy_parser),
which is not maintained anymore.

## Features

- supporting v1.0, v1.0.3, v1.1.
- decoding encrypted message, v1.0, v1.0.3 only. (v1.1 not yet)
- calculating NwkSKey, AppSKey from the join messages with AppKey.
- calculating MIC based on the wire message so that you can check the integrity.

## Requirement

- Python 3.x is required.
- pycryptodome

## Usage

```
usage: lorawan-parser.py [-h] [--lorawan-version VERSION] [--appkey APPKEY]
                         [--join-request JOIN_R] [--join-accept JOIN_A]
                         [--nwkskey NWKSKEY] [--appskey APPSKEY]
                         [--upper-fcnt UPPER_FCNT] [--from-file FROM_FILE]
                         [-v] [-d]
                         [PHY_PDU_HEXSTR [PHY_PDU_HEXSTR ...]]

LoRaWAN PHY frame parser. The input must be hex strings. You can use stdin to
pass the string.

positional arguments:
  PHY_PDU_HEXSTR        a series or multiple of hex string.

optional arguments:
  -h, --help            show this help message and exit
  --lorawan-version VERSION
                        specify the version of LoRaWAN; 0 as v1.0.x, 1 as
                        v1.1.x.
  --appkey APPKEY       specify AppKey.
  --join-request JOIN_R
                        specify the hex string of the Join Request.
  --join-accept JOIN_A  specify the hex string of the Join Accept/Response.
  --nwkskey NWKSKEY     specify NwkSKey(v1.0.x).
  --appskey APPSKEY     specify AppSKey.
  --upper-fcnt UPPER_FCNT
                        specify the most significant 16-bit of the FCnt in
                        hex.
  --from-file FROM_FILE
                        specify a file or stdin to read the messages.
  -v                    enable verbose mode.
  -d                    increase debug mode.
```

## How to pass the hex string of the data

You can put the hex string of the LoRaWAN PHY Payload into the arguments.
The following string are decoded as a same string.  i.e. '01 02 03 04'

    01020304
    0102 0304
    01.02.03.04
    0x01 0x02 0x03 0x04
    0x01,0x02,0x03,0x04
    0102,0304

The separater is a new line code.
If you make a file containing some lines of the hex string like below.

    01020304
    05060708
    0a0b0c0d

The parser can decode each of them separately.
Don't forget to specify "-" or "stdin" as the argument to pass the content of
the file from the stdin. e.g.

    cat file | lorawan-parser.py --from-file -

## How to use

It will parse the hex string of LoRaWAN PHY Payload
and show the result.
The following three examples show Join Request, Join Response.

e.g. Join Request

```
% lorawan-parser.py \
    --appkey BEEF000102030405060708090A0B0C0D \
    00050403020100efbe050403020100efbe87bcc54c5b5f
=== PHYPayload ===
## MHDR : x 00
  MType : Join Request
  RFU : b 000
  Major : LoRaWAN R1
## JoinReq : x 050403020100efbe050403020100efbe87bc
  AppEUI : x beef000102030405
  DevEUI : x beef000102030405
  DevNonce : x bc87
## MIC
  MIC in frame : x 5f5b4cc5
  MIC Derived  : x 5f5b4cc5
```

e.g. Join Response

```
% lorawan-parser.py \
    --appkey BEEF000102030405060708090A0B0C0D \
    20b46c0022dae91f38e172ac0312d4bc5b
=== PHYPayload ===
## MHDR : x 20
  MType : Join Accept
  RFU : b 000
  Major : LoRaWAN R1
## JoinAccept : x b46c0022dae91f38e172ac03
  AppNonce : x 4c5247
  NetID : x 000015
    NwkID : b 0000000
  DevAddr : x 2bbe0934
  DLSettings : x 02
    RFU : b 0
    RX1DROffset : 0
    RX2DataRate : 2
  RxDelay : 1 sec
## MIC
  MIC in frame : x 223195d7
  MIC Derived  : x 223195d7
```

If you can put a pair of messages of Join Request and Join Response
in OTAA mode, it will calculate both NwkSkey and AppSkey with AppKey.
And, it will decrypt all encrypted field and calculate MIC.
The -v option always shows the detail.

e.g. Unconfirmed Data Up

```
% lorawan-parser.py -v \
    --appkey BEEF000102030405060708090A0B0C0D \
    --join-request 00050403020100efbe050403020100efbe87bcc54c5b5f \
    --join-accept 20b46c0022dae91f38e172ac0312d4bc5b \
    403409be2b80000002c7fb8963476d5bf4090e6b867a40b597047241eb80aef79df6
## Calculated Keys
  NwkSKey: x 70ff6652c80bcee90b21f2d74bf336b2
  AppSkey: x 51ebd6666d77121b3782ef59a252e013
=== PHYPayload ===
  PDU : x 403409be2b80000002c7fb8963476d5bf4090e6b867a40b597047241eb80aef79df6
## MHDR : x 40 [b 01000000]
  MType : Unconfirmed Data Up [b 010]
  RFU : b 000
  Major : LoRaWAN R1 [b 00]
## MACPayload : x 3409be2b80000002c7fb8963476d5bf4090e6b867a40b597047241eb80
  FHDR : x 3409be2b800000
    DevAddr : x 2bbe0934 [x 3409be2b]
    FCtrl : x 80 [b 10000000]
      ADR : b 1
      ADRACKReq : b 0
      ACK : b 0
      RFU : b 0
      FOptsLen : 0 [b 0000]
    FCnt : 0 [x 00000000]
    FPort : 2 [x 02]
## FRMPayload (Application Data) : x c7fb8963476d5bf4090e6b867a40b597047241eb80
  AppData : x 8105000a14033e0000000000000e7e09420a8c0000
## MIC
  MIC in frame : x f69df7ae [x aef79df6]
  MIC Derived  : x f69df7ae
```

If you use the -v option for the message containing MAC Commands,
you can see a short description of each command like below:

```
./lorawan-parser.py -v \
    --nwkskey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAABB \
    --appskey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAABB \
    40,B2,00,EF,BE,9A,03,00,03,07,05,07,07,03,07,03,10,04,02,09,AA,50,B1,F0,79,2F,31,AD,9C,63,78,5F,83,8D,95,C6,FE,81,D2,97,09,BA,3C,6E,19,B7,71,43,7C,  -v
=== PHYPayload ===
  PDU : x 40b200efbe9a0300030705070703070310040209aa50b1f0792f31ad9c63785f838d95c6fe81d29709ba3c6e19b771437c
## MHDR : x 40 [b 01000000]
  MType : Unconfirmed Data Up [b 010]
  RFU : b 000
  Major : LoRaWAN R1 [b 00]
## MACPayload : x b200efbe9a0300030705070703070310040209aa50b1f0792f31ad9c63785f838d95c6fe81d29709ba3c6e19
  FHDR : x b200efbe9a030003070507070307031004
    DevAddr : x beef00b2 [x b200efbe]
    FCtrl : x 9a [b 10011010]
      ADR : b 1
      ADRACKReq : b 0
      ACK : b 0
      RFU : b 1
      FOptsLen : 10 [b 1010]
    FCnt : 3 [x 00000003]
    FOpts : x 03070507070307031004
## MAC Command (No. CMD CID DIR [MSG])
    1. LinkADRAns : 0x03 Uplink [x 0705]
      Status : x 07 [b 00000111]
        RFU : b 00000
        Power ACK : 1
          * DETAIL: The device is able to operate at or below the requested
                    power level,, or the TXPower field of the request was
                    set to 15, meaning it shall be ignored
        Data_rate_ACK : 1
          * DETAIL: The data rate was successfully set or the DataRate
                    field of the request was set to 15, meaning it was
                    ignored
        Channel_mask_ACK : 1
          * DETAIL: The channel mask sent was successfully interpreted. All
                    currently defined channel states were set according to
                    the mask.
    2. RXParamSetupAns : 0x05 Uplink [x 0707]
      Status : x 07 [b 00000111]
        RFU : b 00000
        RX1DRoffset ACK : b 1
          * DETAIL: RX1DRoffset was successfully set.
        RX2 Data rate ACK : b 1
          * DETAIL: RX2 slot channel was successfully set.
        Channel ACK : b 1
          * DETAIL: RX2 slot channel was successfully set.
    3. NewChannelAns : 0x07 Uplink [x 0307]
      Status : x 03 [b 00000011]
        RFU : b 000000
        Data rate range ok : b 1
          * DETAIL: The data rate range is compatible with the
                    possibilities of the end-device.
        Channel frequency ok : b 1
          * DETAIL: The device is able to use this frequency.
    4. NewChannelAns : 0x07 Uplink [x 0310]
      Status : x 03 [b 00000011]
        RFU : b 000000
        Data rate range ok : b 1
          * DETAIL: The data rate range is compatible with the
                    possibilities of the end-device.
        Channel frequency ok : b 1
          * DETAIL: The device is able to use this frequency.
    5. PingSlotInfoReq : 0x10 Uplink [x 04]
      PingSlotParam : x 04
        RFU : b 00000
        Periodicity : 4 [b 100]
          pingSlotPeriod : 16 sec
          * DETAIL: Periodicity = 0 means that the end-device opens a ping
                    slot every second. Periodicity = 7, every 128 seconds
                    which is the maximum ping period supported by the
                    LoRaWAN Class B specification.
    FPort : 2 [x 02]
## FRMPayload (Application Data) : x 09aa50b1f0792f31ad9c63785f838d95c6fe81d29709ba3c6e19
  AppData : x 000009c400000000000000000000000000000000000000000000
## MIC
  MIC in frame : x 7c4371b7 [x b771437c]
  MIC Derived  : x 7c4371b7
```

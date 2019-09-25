#!/usr/bin/env python

import sys
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from lorawan_a2b_hex import a2b_hex
from lorawan_parser import parse_phy_pdu
from lorawan_cipher import lorawan_get_keys

ap = ArgumentParser(
        description="""
        LoRaWAN PHY Payload parser.
        The input must be hex strings.
        You can use stdin to pass the string.
        """,
        formatter_class=ArgumentDefaultsHelpFormatter)
ap.add_argument("phy_pdu", metavar="PHY_PDU_HEXSTR", type=str, nargs='*',
                help="a series or multiple of hex string.")
# required to decode Join-Accept.
ap.add_argument("--appkey", "--AppKey", action="store", dest="appkey",
                help="specify AppKey.")
# required to decode messages in OTAA.
ap.add_argument("--join-request", action="store", dest="join_r",
                help="specify the hex string of the Join Request.")
ap.add_argument("--join-accept", action="store", dest="join_a",
                help="specify the hex string of the Join Accept/Response.")
# required to decode messages in ABP.
ap.add_argument("--nwkskey", "--NwkSKey", action="store", dest="nwkskey",
                help="specify NwkSKey(v1.0.x).")
ap.add_argument("--appskey", "--AppSKey", action="store", dest="appskey",
                help="specify AppSKey.")
#
ap.add_argument("--from-file", action="store", dest="from_file",
                help="specify a file or stdin to read the messages.")
#
ap.add_argument("--upper-fcnt", action="store", dest="upper_fcnt",
                default="0000",
                help="specify the most significant 16-bit of the FCnt in hex.")
ap.add_argument("--lorawan-version", action="store", dest="version",
                default="1.0.3",
                # 1.0, 1.0.3, 1.1
                help="specify the version of LoRaWAN; 1.0, 1.0.3, or 1.1")
#ap.add_argument("-b", action="store", dest="beacon_rfu", default=2,
#                help="specify the number of bytes of the RFU in the beacon.")
#
ap.add_argument("--string-type", action="store", dest="string_type",
                default="hexstr",
                help="""specify the type of string of phy_pdu,
                either hexstr or base64.""")
ap.add_argument("-v", action="store_true", dest="verbose",
                help="enable verbose mode.")
ap.add_argument("-d", action="append_const", dest="_f_debug", default=[],
    const=1, help="increase debug mode.")
opt = ap.parse_args()
opt.debug_level = len(opt._f_debug)

# set NwkSKey and AppSKey
nwkskey = a2b_hex(opt.nwkskey)
appskey = a2b_hex(opt.appskey)
appkey = a2b_hex(opt.appkey)
# override the keys if the messages and appkey are specified.
if opt.join_r is not None and opt.join_a is not None:
    if appkey is not None:
        msg_join_r = parse_phy_pdu(a2b_hex(opt.join_r,
                                           string_type=opt.string_type),
                                   appkey=appkey, option=opt,
                                   parse_only=(False if opt.debug_level > 1 else
                                               True))
        msg_join_a = parse_phy_pdu(a2b_hex(opt.join_a,
                                           string_type=opt.string_type),
                                   appkey=appkey, option=opt,
                                   parse_only=(False if opt.debug_level > 1 else
                                               True))
        #
        keys = lorawan_get_keys(appkey,
                                devnonce=msg_join_r["body"]["devnonce"],
                                appnonce=msg_join_a["body"]["appnonce"],
                                netid=msg_join_a["body"]["netid"])
        nwkskey = keys["nwkskey"]
        appskey = keys["appskey"]
        if opt.verbose:
            print("## Calculated Keys")
            print("  NwkSKey: x {}".format(nwkskey.hex()))
            print("  AppSKey: x {}".format(appskey.hex()))
    else:
        raise ValueError("ERROR: appkey is required to produce NwkSKey and AppSKey.")

if opt.from_file:
    if opt.from_file in ["-", "stdin"]:
        fd = sys.stdin
    else:
        fd = open(opt.from_file)
    for line in fd:
        parse_phy_pdu(a2b_hex(line, string_type=opt.string_type),
                      nwkskey=nwkskey, appskey=appskey, appkey=appkey,
                      version=opt.version, upper_fcnt=a2b_hex(opt.upper_fcnt),
                      option=opt)
else:
    if len(opt.phy_pdu) == 0:
        ap.print_help()
        exit(0)
    parse_phy_pdu(a2b_hex(opt.phy_pdu, string_type=opt.string_type),
                  nwkskey=nwkskey, appskey=appskey, appkey=appkey,
                  version=opt.version, upper_fcnt=a2b_hex(opt.upper_fcnt),
                  option=opt)


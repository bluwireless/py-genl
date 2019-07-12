# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2017-2019 Blu Wireless Technology

"""
Helpers and constants for netlink operations
"""

import errno
import os
import struct
import time

from collections import namedtuple


# constants for socket():
NETLINK_GENERIC = 16
SOL_NETLINK = 270
NETLINK_ADD_MEMBERSHIP = 1

# Netlink flags
NLM_F_REQUEST = 1
NLM_F_ACK = 4

# Netlink message types
NLMSG_ERROR = 0x02
GENL_ID_CTRL = 0x10

# Generic netlink protocol versions
GNL_FAMILY_VERSION = 1
NL80211_VERSION = 1

# structs
NL_HEADER_FMT = "@IHHII"
NL_HEADER_LEN = struct.calcsize(NL_HEADER_FMT)

GNL_HEADER_FMT = "@BBH"
GNL_HEADER_LEN = struct.calcsize(GNL_HEADER_FMT)

NLMessageHeader = namedtuple(
    "NLMessage", ['length', 'mtype', 'flags', 'seq', 'port'])
GNLMessageHeader = namedtuple(
    "GNLMessageHeader", ['cmd', 'version', 'reserved'])
GNLAttribute = namedtuple("GNLAttribute", ['length', 'atype', 'data'])
NLMessage = namedtuple("NLMessage", ['nl_header', 'gnl_header', 'attributes'])

# Generic netlink family for talking to cfg80211
NL80211_FAMILY_NAME = "nl80211"


class NetlinkError(Exception):
    """A failure during the netlink operation"""


def align(size):
    # The 1 << 64 -1 is because python ints don't expose two's complement
    return (size + 0x03) & (((1 << 64) - 1) - 3)


def pad(data):
    padding_len = align(len(data)) - len(data)
    return data + (b'\0' * padding_len)


def get_genl_message(payload=None, mtype=0, cmd=0, version=0, flags=0,
                     seq=None, port=None):
    length = NL_HEADER_LEN + GNL_HEADER_LEN + len(payload)
    padded_length = align(length)
    padding = b'\0' * (padded_length - length)

    nl_header = NLMessageHeader(
        length=padded_length,
        mtype=mtype,
        flags=flags,
        seq=seq or int(time.time()),
        port=port or os.getpid())

    genl_header = GNLMessageHeader(cmd=cmd, version=version, reserved=0)

    return (struct.pack(NL_HEADER_FMT, *nl_header) +
            struct.pack(GNL_HEADER_FMT, *genl_header) +
            payload + padding)


def parse_nl_message(nl_message):
    header_bytes = nl_message[:NL_HEADER_LEN]

    nl_header = NLMessageHeader(*struct.unpack(NL_HEADER_FMT, header_bytes))
    nl_body = nl_message[align(NL_HEADER_LEN):]

    return nl_header, nl_body


def parse_genl_message(genl_message):
    nl_header, nl_body = parse_nl_message(genl_message)

    genl_header_bytes = nl_body[:GNL_HEADER_LEN]
    genl_header = GNLMessageHeader(*struct.unpack(GNL_HEADER_FMT,
                                                  genl_header_bytes))
    genl_body = nl_body[align(GNL_HEADER_LEN):]

    return nl_header, genl_header, genl_body


def parse_nl_error(data):
    error_fmt = "@i"
    error = struct.unpack(error_fmt, data[0:struct.calcsize(error_fmt)])
    return error[0]


def parse_generic_attributes(data):
    index = 0

    attrib_hdr_fmt = "@HH"
    attrib_hdr_len = struct.calcsize(attrib_hdr_fmt)
    padded_attrib_hdr_len = align(attrib_hdr_len)

    attributes = []

    while index < len(data):
        nla_len, nla_type = struct.unpack(
            attrib_hdr_fmt, data[index:index + attrib_hdr_len])

        nla_data = data[index + padded_attrib_hdr_len:index + nla_len]

        index += align(nla_len)
        assert nla_len

        attributes.append(GNLAttribute(nla_len, nla_type, nla_data))

    return attributes


def wait_for_ack(sock):
    data = sock.recv(4096)
    nl_header, nl_body = parse_nl_message(data)
    if nl_header.mtype != NLMSG_ERROR:
        raise NetlinkError("Invalid response to vendor command (%s)"
                           % nl_header.mtype)
    error = abs(parse_nl_error(nl_body))
    if error != 0:
        raise NetlinkError(
            "Vendor command failed: %s [%s]"
            % (os.strerror(error), errno.errorcode[error]))

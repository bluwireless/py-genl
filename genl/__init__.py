# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2019 Blu Wireless Technology

import ctypes
import ctypes.util
from collections import namedtuple
import socket
import os
import errno

from .nlattr import NlAttrSchema
from .netlink import (NLM_F_REQUEST,
                      GENL_ID_CTRL, GNL_FAMILY_VERSION,
                      NETLINK_GENERIC,
                      NetlinkError,
                      get_genl_message,
                      parse_genl_message)


# From linux/genetlink.h
CTRL_CMD_GETFAMILY = None  # To relax the linter
genl_ctrl_constants = {
    "CTRL_CMD_GETFAMILY": 3,
    "CTRL_ATTR_FAMILY_ID": 1,
    "CTRL_ATTR_FAMILY_NAME": 2,
    "CTRL_ATTR_MCAST_GROUPS": 7,
    "CTRL_ATTR_MCAST_GRP_NAME": 1,
    "CTRL_ATTR_VERSION": 3,
    "CTRL_ATTR_HDRSIZE": 4,
    "CTRL_ATTR_MAXATTR": 5,
    "CTRL_ATTR_OPS": 6,
    "CTRL_ATTR_MCAST_GRP_ID": 2,
}
globals().update(genl_ctrl_constants)


# We'll need to use the GETFAMILY command, which is part of the core generic
# netlink system, to query the system's IDs for nl80211. Define a schema for
# that.
getfamily_spec = [
    {
        "name": "CTRL_ATTR_FAMILY_ID",
        "type": "u16",
    },
    {
        "name": "CTRL_ATTR_FAMILY_NAME",
        "type": "str"
    },
    {
        "name": "CTRL_ATTR_VERSION",
        "type": "u32",
    },
    {
        "name": "CTRL_ATTR_HDRSIZE",
        "type": "u32",
    },
    {
        "name": "CTRL_ATTR_MAXATTR",
        "type": "u32",
    },
    {
        "name": "CTRL_ATTR_OPS",
        "type": "bytes",  # Actually a nested thing, don't care about it.
    },
    {
        "name": "CTRL_ATTR_MCAST_GROUPS",
        "type": "list",
        "subelem_type": [
            {
                "name": "CTRL_ATTR_MCAST_GRP_NAME",
                "type": "str"
            },
            {
                "name": "CTRL_ATTR_MCAST_GRP_ID",
                "type": "u32"
            }
        ],
    }
]
getfamily_schema = NlAttrSchema.from_spec(getfamily_spec, genl_ctrl_constants)


GenlFamilyInfo = namedtuple("GenlFamilyInfo", ["id", "mcast_groups"])


def lookup_genl_family(family_name):
    """
    Look up a generic netlink family by name

    Returns a GenlFamilyInfo with the numerical family ID and the IDs of the
    multicast groups it exposes
    """
    cmd = get_genl_message(
        mtype=GENL_ID_CTRL,
        flags=NLM_F_REQUEST,
        cmd=CTRL_CMD_GETFAMILY,
        version=GNL_FAMILY_VERSION,
        payload=getfamily_schema.build(family_name=family_name))

    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    try:
        sock.bind((0, 0))
        sock.sendall(cmd)
        data = sock.recv(4096)
        nl_header, genl_header, genl_body = parse_genl_message(data)
        response = getfamily_schema.parse(genl_body)

        mcast_groups = {}
        for entry in response["CTRL_ATTR_MCAST_GROUPS"]:
            group_name = entry["CTRL_ATTR_MCAST_GRP_NAME"].strip()
            mcast_groups[group_name] = entry["CTRL_ATTR_MCAST_GRP_ID"]

        return GenlFamilyInfo(response["CTRL_ATTR_FAMILY_ID"], mcast_groups)
    finally:
        sock.close()


# Make if_nametoindex(3) and if_indextoname(3) from libc available (for newer
# Pythons this is in the standard library anyway).
_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_if_nametoindex = _libc.if_nametoindex
_if_nametoindex.argtypes = [ctypes.c_char_p]
_if_nametoindex.restype = ctypes.c_uint

_if_indextoname = _libc.if_indextoname
_if_indextoname.argtypes = [ctypes.c_uint, ctypes.c_char_p]
_if_indextoname.restype = ctypes.c_char_p

IF_NAMESIZE = 16


def if_nametoindex(name):
    index = _if_nametoindex(name.encode("ascii"))

    if index == 0:
        op_errno = ctypes.get_errno()
        if op_errno == errno.ENODEV:
            raise NetlinkError("no interface called '%s'" % name)
        else:
            raise OSError(op_errno, os.strerror(op_errno))

    return index


def if_indextoname(index):
    name = _if_indextoname(index, b" " * IF_NAMESIZE)

    if not name:
        op_errno = ctypes.get_errno()
        if op_errno == errno.ENXIO:
            raise NetlinkError("no interface with index %d" % index)
        else:
            raise OSError(op_errno, os.strerror(op_errno))

    return name.decode("ascii")

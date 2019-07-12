#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2019 Blu Wireless Technology

"""
Example program to dump a wireless interface info from nl80211

Pass interface name as sole argument
"""

from sys import argv
import socket

from genl.nl80211 import nl80211_schema, NL80211_CMD_GET_INTERFACE
from genl import lookup_genl_family, if_nametoindex
from genl.netlink import (get_genl_message, parse_genl_message,
                          NETLINK_GENERIC, NLM_F_REQUEST)


def main():
    # We need to look up the family ID which will go in the nl header's type
    # field. This also gives us the IDs we'd need to subscribe the socket to any
    # broadcast groups exposed by the family.
    family = lookup_genl_family("nl80211")

    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    sock.bind((0, 0))

    # We use get_genl_message to build a Generic Netlink message. The nl80211
    # command goes in the cmd field of the genl header.
    # The payload is built using the canned nl0211 schema, using kwargs to
    # specify the attribute values used to express command params.
    # We could instead pass a dict, in which case we'd use the full attribute
    # names instead of shortened Pythonic names, e.g. instead of ifindex=foo
    # we could pass {"NL80211_ATTR_IFINDEX": foo}.
    msg = get_genl_message(
        mtype=family.id,
        flags=NLM_F_REQUEST,
        cmd=NL80211_CMD_GET_INTERFACE,
        payload=nl80211_schema.build(ifindex=if_nametoindex(argv[1])))
    sock.send(msg)

    # Note the fixed size receive. This library lacks support for multi-part
    # messages.
    msg = sock.recv(8192)
    # Parse out the nl and genl header
    nl_header, genl_header, payload = parse_genl_message(msg)
    # Now we use the same canned schema to parse then attributes in the reply
    # payload
    info = nl80211_schema.parse(payload)

    # The attributes can be accessed like a dict; in this case the keys are the
    # full attribute names. For exmple if your WiFi is connected to a network ,
    # these prints will include a line something like:
    #   NL80211_ATTR_SSID = Darude-LANStorm
    print("Raw data:")
    for key in info:
        print("  {} = {}".format(key, info[key]))

    # Then for convenience we can also access the attributes as Python
    # attributes using nicer names. The nl80211 schema (see nl80211.py) doesn't
    # specify the names for the Python attributes, so we get the default
    # behaviour, which is that the Python names are determined by finding the
    # full name's unique suffix amongst its siblings and lower-casing it.
    # So instead of info["NL80211_ATTR_SSID"] we can just access info.ssid.
    print("\nname: '{}' | MAC: {} | Current SSID: '{}'".format(
        info.ifname,
        ":".join("{:02x}".format(b) for b in info.mac),
        info.ssid))

if __name__ == "__main__":
    main()

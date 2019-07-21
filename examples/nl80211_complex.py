#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2019 Brendan Jackman

"""
Example program to dump wireless interface info from nl80211

Like nl80211_dump.py but more complicated, using more attributes, demonstrating
how attributes nest. This will likely print lots of warnings because the nl80211
schema is incomplete.

Pass interface name as sole argument
"""

from sys import argv
import socket

from genl.nl80211 import (nl80211_schema,
                          NL80211_CMD_GET_INTERFACE, NL80211_CMD_GET_WIPHY)
from genl import lookup_genl_family, if_nametoindex
from genl.netlink import (get_genl_message, parse_genl_message,
                          NETLINK_GENERIC, NLM_F_REQUEST)


# We need to look up the family ID which will go in the nl header's type
# field. This also gives us the IDs we'd need to subscribe the socket to any
# broadcast groups exposed by the family.
nl80211_family = lookup_genl_family("nl80211")


def do_nl80211_query(sock, cmd, **kwargs):
    """Call an nl80211 cmd (with **kwargs) and return the parsed response"""
    # We use get_genl_message to build a Generic Netlink message. The nl80211
    # command goes in the cmd field of the genl header.
    # The payload is built using the canned nl0211 schema, using kwargs to
    # specify the attribute values used to express command params.
    msg = get_genl_message(
        mtype=nl80211_family.id,
        flags=NLM_F_REQUEST,
        cmd=cmd,
        payload=nl80211_schema.build(**kwargs))
    sock.send(msg)

    msg = sock.recv(8192)
    nl_header, genl_header, payload = parse_genl_message(msg)
    return nl80211_schema.parse(payload)


def main():
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    sock.bind((0, 0))

    # Use GET_INTERFACE to get some basic info and the wiphy index
    iface_info = do_nl80211_query(sock, NL80211_CMD_GET_INTERFACE,
                                  ifindex=if_nametoindex(argv[1]))
    # Now we can use GET_WIPHY to get more detailed info
    wiphy_info = do_nl80211_query(sock, NL80211_CMD_GET_WIPHY,
                                  wiphy=iface_info.wiphy)

    # Dump the basic info
    print("Interface name: '{}' | MAC: {} | Current SSID: '{}'".format(
        iface_info.ifname,
        # Mac address is just bytes, up to us to pretty-print it
        ":".join("{:02x}".format(b) for b in iface_info.mac),
        iface_info.ssid))

    # As an example to illustrate that commands can nest, let's dump all the
    # supported frequencies and their associated max TX power
    print("Supported frequencies:")
    for band_idx, band in enumerate(wiphy_info.wiphy_bands):
        print("  Band {}:".format(band_idx))
        for freq_info in band.freqs:
            # To annoy RF engineers TX power is expressed mBm, hence division
            # by 100
            print("    {}Mhz (up to {}dBm)".format(
                freq_info.freq, freq_info.max_tx_power / 100.))


if __name__ == "__main__":
    main()

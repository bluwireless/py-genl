#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2019 Brendan Jackman

"""
Program to run nl80211 queries using JSON

This uses the nl80211 schema provided with this library to run nl80211 commands
with the parameters provided as JSON objects, and the results printed as JSON
objects.

The keys in the JSON objects will be the full names of the attribute types (for
example "NL80211_ATTR_INTERFACE".

The schema in the library is incomplete, so depending on your system and the
command you run, you will probably get warnings about unknown attributes
appearing in the response from the kernel.

Try a command like this (find index of your wireless interface using "ip link
show"):
pipenv run nl80211_json.py NL80211_CMD_GET_INTERFACE '{"NL80211_ATTR_IFINDEX": 3}'
"""

import json
from argparse import ArgumentParser
import socket
from collections.abc import Mapping

from genl.nl80211 import nl80211_schema, nl80211_constants
from genl.netlink import (parse_nl_message, parse_nl_error,
                          get_genl_message, parse_genl_message,
                          NLMSG_ERROR,
                          NETLINK_GENERIC, NLM_F_REQUEST)
from genl import lookup_genl_family

# The default JSON encoder doesn't fully convert things to dicts automatically,
# nor does it know a way to serialise bytes
class MyJsonEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Mapping):
            return dict(o)
        if isinstance(o, bytes):
            # Will this actually deserialise cleanly all the time? Not sure.
            return "".join(r"\x{:02x}".format(b) for b in o)
        return super().default(o)


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("command", help="Name of nl80211 command to call")
    parser.add_argument("params", help="JSON string with command params")
    args = parser.parse_args()


    family = lookup_genl_family("nl80211")

    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    sock.bind((0, 0))

    msg = get_genl_message(
        mtype=family.id,
        flags=NLM_F_REQUEST,
        cmd=nl80211_constants[args.command],
        payload=nl80211_schema.build(json.loads(args.params)))
    sock.send(msg)

    msg = sock.recv(8192)
    nl_header, nl_payload = parse_nl_message(msg)
    if nl_header.mtype == NLMSG_ERROR:
        raise RuntimeError("Error {} from command"
                           .format(parse_nl_error(nl_payload)))

    nl_header, genl_header, payload = parse_genl_message(msg)
    print(json.dumps(nl80211_schema.parse(payload),
                     cls=MyJsonEncoder, indent=4))


if __name__ == "__main__":
    main()

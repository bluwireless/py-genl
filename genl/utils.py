# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2019 Blu Wireless Technology

# This is just debug code


def hexdump_bufs(bufs):
    longest_buf_len = max(len(b) for b in bufs)

    def to_hex_lines(buf):
        # First convert to a list of single-byte hex strings.
        # Iterating over bytes in Python 2 is stupid hence use of ord.
        hex_bytes = list("{:02x}".format(b) for b in buf)
        # Pad out the shorter list with spaces
        hex_bytes += ["  "] * (longest_buf_len - len(buf))

        hex_lines = []
        while hex_bytes:
            hex_lines.append(" ".join(hex_bytes[:4]))
            hex_bytes = hex_bytes[4:]

        return hex_lines

    ret = ""
    for lines in zip(*(to_hex_lines(b) for b in bufs)):
        ret += " | ".join(lines) + "\n"

    return ret

from collections import OrderedDict
import struct
import sys
from unittest import TestCase, SkipTest
try:
    from unittest.mock import Mock, patch
except ImportError:
    # Must be on Python 2, need to use 3rd party package
    from mock import Mock, patch

from genl import (lookup_genl_family, CTRL_CMD_GETFAMILY, GenlFamilyInfo,
                  CTRL_ATTR_FAMILY_NAME, CTRL_ATTR_FAMILY_ID,
                  CTRL_ATTR_MCAST_GROUPS, CTRL_ATTR_MCAST_GRP_NAME,
                  CTRL_ATTR_MCAST_GRP_ID)

from genl.netlink import (GENL_ID_CTRL, GNL_FAMILY_VERSION,
                          NLM_F_REQUEST, pad, get_genl_message)
from genl.nl80211 import (nl80211_schema,
                          NL80211_ATTR_WIPHY_RETRY_SHORT,
                          NL80211_ATTR_NOACK_MAP, NL80211_ATTR_VENDOR_SUBCMD,
                          NL80211_ATTR_WDEV, NL80211_ATTR_STA_SUPPORTED_RATES,
                          NL80211_ATTR_IFTYPE_EXT_CAPA, NL80211_ATTR_IFTYPE,
                          NL80211_ATTR_EXT_CAPA, NL80211_ATTR_KEY,
                          NL80211_KEY_DEFAULT, NL80211_KEY_IDX)
from genl.nlattr import NlAttrSchema


# Helpers for creating Netlink attributes of various types


def _nla(attrib_fmt, attrib_id, data):
    return pad(struct.pack(
        attrib_fmt, struct.calcsize(attrib_fmt), attrib_id, data))


def nla_u8(attrib_id, data):
    return _nla("=HHB", attrib_id, data)


def nla_u16(attrib_id, data):
    return _nla("=HHH", attrib_id, data)


def nla_s16(attrib_id, data):
    return _nla("=HHh", attrib_id, data)


def nla_u64(attrib_id, data):
    return _nla("=HHQ", attrib_id, data)


def nla_u32(attrib_id, data):
    return _nla("=HHI", attrib_id, data)


def nla_flag(attrib_id):
    fmt = "=HH"
    return struct.pack(fmt, struct.calcsize(fmt), attrib_id)


def nla(attrib_id, data):
    return _nla("@HH%ds" % len(data), attrib_id, data)


def nla_str(attrib_id, data):
    return nla(attrib_id, data.encode("ascii") + b"\0")


class SocketMock(Mock):
    """Helper for getting the messages sent into a mocked socket"""
    def get_sent_messages(self):
        # Get all the sendall calls, pick out the first arg of each and put
        # them in a list.
        messages = []
        for call in self.sendall.call_args_list:
            args, kwargs = call
            messages.append(args[0])
        return messages


def assert_bufs_equal(buf1, buf2):
    """Asserter that provides a useful hexdump on failures"""
    if not buf1 == buf2:
        err = "Buffers don't match\nbuf1          buf2\n"

        longest_buf_len = max(len(buf1), len(buf2))

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

        for buf1_line, buf2_line in zip(to_hex_lines(buf1),
                                        to_hex_lines(buf2)):
            error_here = buf1_line != buf2_line
            err += "{} | {} {}\n".format(buf1_line, buf2_line,
                                         "<!" if error_here else "")

        raise AssertionError(err)


@patch("socket.socket", new_callable=SocketMock)
class TestGenlCtrl(TestCase):
    def test_lookup_genl_family(self, socket_mock):
        sock = socket_mock.return_value

        msg = get_genl_message(
            nla_u16(CTRL_ATTR_FAMILY_ID, 123) +
            nla(CTRL_ATTR_MCAST_GROUPS,
                nla(1,
                    nla_str(CTRL_ATTR_MCAST_GRP_NAME, "foo") +
                    nla_u32(CTRL_ATTR_MCAST_GRP_ID, 1)) +
                nla(2,
                    nla_str(CTRL_ATTR_MCAST_GRP_NAME, "bar") +
                    nla_u32(CTRL_ATTR_MCAST_GRP_ID, 2))))

        sock.recv.side_effect = [msg]

        family = lookup_genl_family("dummy_family")

        [msg] = sock.get_sent_messages()
        assert_bufs_equal(
            msg,
            get_genl_message(
                mtype=GENL_ID_CTRL,
                flags=NLM_F_REQUEST,
                cmd=CTRL_CMD_GETFAMILY,
                version=GNL_FAMILY_VERSION,
                payload=nla_str(CTRL_ATTR_FAMILY_NAME, "dummy_family")))

        self.assertEqual(family, GenlFamilyInfo(123, {"foo": 1, "bar": 2}))


class TestNl80211(TestCase):
    # Here's a (nonsensical) nl80211 message payload trying to hit as many
    # attribute types as possible.
    test_buf = (
        nla_u8(NL80211_ATTR_WIPHY_RETRY_SHORT, 1) +
        nla_u16(NL80211_ATTR_NOACK_MAP, 2) +
        nla_u32(NL80211_ATTR_VENDOR_SUBCMD, 3) +
        nla_u64(NL80211_ATTR_WDEV, 4) +
        nla(NL80211_ATTR_STA_SUPPORTED_RATES, b"\x05\x06\x07") +
        nla(NL80211_ATTR_IFTYPE_EXT_CAPA,
            nla(1,
                nla_u32(NL80211_ATTR_IFTYPE, 8) +
                nla(NL80211_ATTR_EXT_CAPA, b"\x09")) +
            nla(2,
                nla_u32(NL80211_ATTR_IFTYPE, 10) +
                nla(NL80211_ATTR_EXT_CAPA, b"\x0b"))) +
        nla(NL80211_ATTR_KEY,
            nla_flag(NL80211_KEY_DEFAULT) +
            nla_u8(NL80211_KEY_IDX, 13))
    )

    # Here's a dictionary expressing the attributes that should equate to the
    # buffer above
    test_attrs = OrderedDict([
        ("NL80211_ATTR_WIPHY_RETRY_SHORT", 1),
        ("NL80211_ATTR_WIPHY_RETRY_SHORT", 1),
        ("NL80211_ATTR_NOACK_MAP", 2),
        ("NL80211_ATTR_VENDOR_SUBCMD", 3),
        ("NL80211_ATTR_WDEV", 4),
        ("NL80211_ATTR_STA_SUPPORTED_RATES", [5, 6, 7]),

        ("NL80211_ATTR_IFTYPE_EXT_CAPA", [
            OrderedDict([
                ("NL80211_ATTR_IFTYPE", 8),
                ("NL80211_ATTR_EXT_CAPA", b"\x09")]),
            OrderedDict([
                ("NL80211_ATTR_IFTYPE", 10),
                ("NL80211_ATTR_EXT_CAPA", b"\x0b")])]),
        ("NL80211_ATTR_KEY", OrderedDict([
            ("NL80211_KEY_DEFAULT", True),
            ("NL80211_KEY_IDX", 13)]))])

    def test_build_kwargs(self):
        buf = nl80211_schema.build(
            wiphy_retry_short=1,
            noack_map=2,
            vendor_subcmd=3,
            wdev=4,
            sta_supported_rates=[5, 6, 7],
            iftype_ext_capa=[
                {"NL80211_ATTR_IFTYPE": 8, "NL80211_ATTR_EXT_CAPA": b"\x09"},
                {"NL80211_ATTR_IFTYPE": 10, "NL80211_ATTR_EXT_CAPA": b"\x0b"},
            ],
            key={"NL80211_KEY_DEFAULT": True, "NL80211_KEY_IDX": 13})

        # Can't guarantee the order will be preserved on older Pythons
        # https://docs.python.org/3/whatsnew/3.6.html#whatsnew36-pep468
        # (We still built the message anyway, at least we know it didn't crash)
        if sys.version_info < (3, 6):
            raise SkipTest(
                "Here's a shilling, young fellow! Get yourself a new Python")

        assert_bufs_equal(buf, self.test_buf)

    def test_build_dict(self):
        buf = nl80211_schema.build(self.test_attrs)
        assert_bufs_equal(buf, self.test_buf)

    def test_parse(self):
        attrs = nl80211_schema.parse(self.test_buf)

        # Check accessing attributes dict-style
        self.assertEqual(dict(attrs), dict(self.test_attrs))

        # Check access attributes as python attributes
        self.assertEqual(attrs.wiphy_retry_short, 1)
        self.assertEqual(attrs.noack_map, 2)
        self.assertEqual(attrs.vendor_subcmd, 3)
        self.assertEqual(attrs.wdev, 4)
        self.assertEqual(attrs.sta_supported_rates, [5, 6, 7])
        self.assertEqual(attrs.iftype_ext_capa[0].iftype, 8)
        self.assertEqual(attrs.iftype_ext_capa[0].ext_capa, b"\x09")
        self.assertEqual(attrs.key.default, True)
        self.assertEqual(attrs.key.idx, 13)


class TestNlAttrSchema(TestCase):
    def test_flag(self):
        ids = {"ATTR_FOO": 1}
        schema = NlAttrSchema.from_spec([
            {
                "name": "ATTR_FOO",
                "type": "flag",
                "python_name": "foo"
            }
        ], ids)

        self.assertEqual(schema.build(foo=False), b"")
        self.assertEqual(schema.build(foo=True), nla_flag(1))
        self.assertEqual(schema.parse(b"").foo, False)
        self.assertEqual(schema.parse(nla_flag(1)).foo, True)

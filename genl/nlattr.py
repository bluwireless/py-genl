# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2019 Blu Wireless Technology

"""
Tools for building and parsing netlink attributes with high-level Python
"""

import struct
import warnings
from collections import OrderedDict
from os.path import commonprefix
try:
    from collections.abc import Mapping  # Python 3
except ImportError:
    from collections import Mapping      # Python 2

from .netlink import pad, NetlinkError, parse_generic_attributes


class NlAttrSet(Mapping):
    """
    Concrete instance of a set of netlink attributes

    This is basically a wrapper for a dictionary that also provides a
    __getattr__ allowing the values to be accessed as python
    attributes. ``name_mapping`` provides the mapping from the python attribute
    names to dictionary keys. This is used, for example, so that the attributes
    in a netlink message might be accessed as either ``attrs["ATTR_FOO"]`` or
    ``attrs.foo``.
    """
    def __init__(self, values, name_mapping):
        self._values = values
        self.name_mapping = name_mapping

    def __getitem__(self, key):
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def __getattr__(self, name):
        if name in self.name_mapping:
            return self[self.name_mapping[name]]
        else:
            raise AttributeError("Don't have {} (available: {})".format(
                name, list(self.name_mapping.keys())))


class NlAttrSchema(object):
    """
    Schema for a set of netlink attributes

    These schemata store information about the attributes that are expected to
    appear in a Generic Netlink message (or part of one). They can be used to
    build a payload from a mapping from attribite names to values, and to parse
    a payload into a similar mapping.

    This class should be constructed via :meth:`from_spec`.
    """
    def __init__(self, subattr_schemata, ids,
                 required_attrs=None, name_mapping=None):
        # This dictionary maps the names of the attributes contained in this
        # attribute set to schema objects that describe/parse/build each
        # attribute payload. These might be further nested schemata.
        self.subattr_schemata = subattr_schemata
        # This dictionary maps symbolic names of attribute types to numerical
        # IDs
        self.ids = ids
        # name_mapping is used to map between short Python names and full
        # netlink attribute ID names (e.g. "ifindex" -> "NL80211_ATTR_IFINDEX")
        self.name_mapping = name_mapping
        self.required_attrs = required_attrs or []

    @classmethod
    def from_spec(cls, spec, ids):
        """
        Create a schema from a spec

        :param spec: This is a list of dictionaries. Each dictionary specifies
            a single attribute that's expected to appear in the message. Each
            dictionary contains these fields:

             - "name": The name of the attribute; this will typically be an
               identifier from an enum in a Linux kernel header file. This
               value must appear as a key in the ``ids`` param.

             - "python_name": The short Python identifier to be used to access
               the attribute in parsed values and identify it when building
               with kwargs. If absent, defaults to lower-case version of the
               unique suffix of "name" among sibling attributes e.g. if
               attribute names are "MY_ATTR_FOO" and "MY_ATTR_BAR", Python
               names default to
               "foo" and "bar".

             - "type": The name of the expected type of the attribute. This
               determines the way in which the attribute is built and
               parsed. Allowed values are:

               - "u8", "u16", "s16", "u32", "u64": Integer of relevant size and
                 signedness
               - "str": Null-terminated ASCII string
               - "bytes": Byte blob
               - "array": Concatenated array of fixed-size
                 sub-elements. "subelem_type" specifies type of those
                 sub-elems.  An example of this in Linux is
                 NL80211_ATTR_STA_SUPPORTED_RATES which is an array of u8
                 values. This is mapped to a Python list.
               - "list": Set of sub-attributes, using attribute IDs 1-N to
                 index sub-elements. This uses the attribute header (which has
                 a length field) allows the sub-elements to have a variable
                 size. An example of this is in Linux is
                 NL80211_ATTR_IFTYPE_EXT_CAPA; this is a nested set of
                 attributes with IDs 1-N, each of which is a _further_ nested
                 set of attributes expressing interface capability info.  This
                 is also mapped to a Python list.
               - Or, another list of attribute entries, representing a
                 directly-nested attribute set. An example of this in Linux is
                 NL80211_ATTR_KEY, where the payload contains further netlink
                 attributes.

             - "subelem_type": For attribute types that represent collections,
               this stores the type of the elements of the collection. This can
               have all the same values as "type".

             - "required": If present and True, :meth:`build` raises an error
               if no value is provided for this attribute

        :param ids: Mapping from attribute names to numerical IDs.
        """
        # In case of direct recursion from this class to itself (i.e. when
        # the spec has an attribute that directly embeds another attribute set)
        # We pass the full spec in as a dict instead of just the list of
        # subattribute specs. Need to convert to that list.
        if isinstance(spec, dict):
            spec = spec["type"]

        common_prefix = commonprefix(list(a["name"] for a in spec))
        if not common_prefix.endswith("_"):
            common_prefix += "_"

        # It would be weird for the ordering to matter semantically, but we use
        # OrderedDict to keep stable ordering so that message content can be
        # predicted byte-for-byte for testing and debugging.
        subattr_schemata = OrderedDict()
        name_mapping = {}
        required_attrs = []
        for field_spec in spec:
            schema_cls = get_schema_class(field_spec)
            subattr_schema = schema_cls.from_spec(field_spec, ids)
            subattr_schemata[field_spec["name"]] = subattr_schema

            if "python_name" in field_spec:
                name_mapping[field_spec["python_name"]] = field_spec["name"]
            else:
                python_name = field_spec["name"][len(common_prefix):].lower()
                name_mapping[python_name] = field_spec["name"]

            if field_spec.get("required", False):
                required_attrs.append(field_spec["name"])

        return cls(subattr_schemata, ids, required_attrs, name_mapping)

    def build(self, _attr_values=None, **kwargs):
        """
        Build an attribute set as bytes from provided values

        Either provide the ``_attr_values`` param, or kwargs, not
        both. ``_attr_values`` is a mapping from attribute names to the
        corresponding attributes' values. If kwargs are passed, they use the
        Python names for the attributes (see the "python_name" field in
        :meth:`from_spec`).
        """
        if bool(_attr_values) == bool(kwargs):
            raise ValueError("Provide exactly one of _attr_values or kwargs")

        if kwargs:
            unknown_kwargs = set(kwargs).difference(self.name_mapping)
            if unknown_kwargs:
                raise ValueError("Unsupported kwargs {} (Supported: {})"
                                 .format(unknown_kwargs,
                                         self.name_mapping.keys()))
            attr_values = {self.name_mapping[k]: v for k, v in kwargs.items()}
        else:
            attr_values = _attr_values

        payload = b""

        # First check for unknown or attribute names or missing values
        unknown_attrs = set(attr_values).difference(self.subattr_schemata)
        if unknown_attrs:
            raise ValueError("Unknown attributes: {}".format(unknown_attrs))
        missing_attrs = set(self.required_attrs).difference(attr_values)
        if missing_attrs:
            raise ValueError("Missing required attributes: {}"
                             .format(missing_attrs))

        # Now iterate over the known attributes and build the message up
        for name, val in attr_values.items():
            val = attr_values[name]
            attr_payload = self.subattr_schemata[name].build(val)

            attrib_header_fmt = "@HH"
            length = struct.calcsize(attrib_header_fmt) + len(attr_payload)
            attr_id = self.ids[name]
            payload += pad(struct.pack(attrib_header_fmt, length, attr_id) +
                           attr_payload)

        return payload

    def parse(self, data):
        """
        Parse an attribute set from bytes to get attribute values

        Returns a :class:`NlAttrSet` with the values of each of the attributes
        found in the data. The mapping between Python names and attribute names
        used in the ``NlAttrSet`` is according to the "python_name" field in
        :meth:`from_spec`
        """
        attr_values = {}

        for attr in parse_generic_attributes(data):
            # Find the name of the attribute with the given type
            for attr_name, attr_type in self.subattr_schemata.items():
                if attr.atype == self.ids[attr_name]:
                    break
            else:
                msg = "Ignoring unknown attribute {}." .format(attr.atype)
                candidates = [n for n, i in self.ids.items()
                              if i == attr.atype]
                if candidates:
                    msg += " Could be {}".format(", ".join(candidates))
                warnings.warn(msg)
                continue

            try:
                attr_values[attr_name] = attr_type.parse(attr.data)
            except NetlinkError:
                raise  # This exception hopefully has a useful message already
            except Exception as e:
                # Add a error message with a bit more info about what went
                # wrong as the stack trace isn't much use.
                raise NetlinkError(
                    "Got '{}' while parsing attribute '{}' of type {}".format(
                        e, attr_name, type(attr_type).__name__))

        missing_attrs = set(self.required_attrs).difference(attr_values)
        if missing_attrs:
            raise NetlinkError(
                "Missing required attributes in parsed message: {}"
                .format(missing_attrs))

        return NlAttrSet(attr_values, self.name_mapping)


schema_classes = {}


# Decorator to register schema classes
def schema_class(cls):
    for name in cls.names:
        schema_classes[name] = cls
    return cls


def get_schema_class(spec):
    if isinstance(spec, list) or isinstance(spec["type"], list):
        # This is the "root" or nested schema (not in the schema_classes dict)
        return NlAttrSchema
    else:
        # Assume spec is a dictionary, find the class like that
        return schema_classes[spec["type"]]


int_type_to_fmt = {
    "u8": "=B",
    "u16": "=H",
    "s16": "=h",
    "u32": "=I",
    "u64": "=Q",
}


@schema_class
class NlAttrSchemaInt(object):
    """Schema for a single integer attribute"""
    names = int_type_to_fmt.keys()

    def __init__(self, fmt):
        self.fmt = fmt
        self.size = struct.calcsize(fmt)

    @classmethod
    def from_spec(cls, spec, ids):
        return cls(int_type_to_fmt[spec["type"]])

    def build(self, val):
        return struct.pack(self.fmt, val)

    def parse(self, data):
        return struct.unpack(self.fmt, data)[0]


@schema_class
class NlAttrSchemaStr(object):
    """Schema for a string attribute"""
    names = ["str"]

    def build(self, val):
        return val.encode("ascii") + b'\0'

    @classmethod
    def from_spec(cls, spec, ids):
        return cls()

    def parse(self, data):
        s = data.decode()
        # Strip off trailing NUL
        if s[-1] == '\0':
            s = s[:-1]
        return s


@schema_class
class NlAttrSchemaBytes(object):
    """Schema for an attribute that's just a byte blob"""
    names = ["bytes"]

    def build(self, data):
        return bytes(data)

    @classmethod
    def from_spec(cls, spec, ids):
        return cls()

    def parse(self, data):
        return data


class NlAttrSchemaCollection(object):
    """Helper class for list and array schemata"""
    @classmethod
    def from_spec(cls, spec, ids):
        if isinstance(spec["subelem_type"], str):
            # For convenience the subelem type can just refer specifically to
            # the name of the type rather than being a dict; convert to the
            # dict.
            subelem_spec = {"type": spec["subelem_type"]}
        else:
            subelem_spec = spec["subelem_type"]

        subelem_schema_cls = get_schema_class(subelem_spec)
        return cls(subelem_schema_cls.from_spec(subelem_spec, ids), ids)


@schema_class
class NlAttrSchemaList(NlAttrSchemaCollection):
    """
    Special attribute schema for "list" attributes

    Netlink attribute IDs are usually semantically significant, but in some
    cases an attribute set just uses IDs 1 through N, with each payload
    containing a nested attribute set (for example the result of a nl80211
    passive scan represents the list of detected BSSs this way). This class
    handles this representation by converting to and from Python lists.
    """
    names = ["list"]

    def __init__(self, subelem_schema, ids):
        self.subelem_schema = subelem_schema
        self.ids = ids

    def build(self, attr_values):
        payload = b""

        for i, val in enumerate(attr_values):
            attr_payload = self.subelem_schema.build(val)

            attrib_header_fmt = "@HH"
            length = struct.calcsize(attrib_header_fmt) + len(attr_payload)
            attr_id = i + 1
            payload += pad(struct.pack(attrib_header_fmt, length, attr_id) +
                           attr_payload)

        return payload

    def parse(self, data):
        attrs = parse_generic_attributes(data)
        if not attrs:
            return []

        # Start with a list of Nones, in case the list is sparse.
        ret = [None for i in range(max(a.atype for a in attrs))]
        for attr in attrs:
            ret[attr.atype - 1] = self.subelem_schema.parse(attr.data)
        return ret


@schema_class
class NlAttrSchemaArray(NlAttrSchemaCollection):
    """
    Special attribute schema for "array" attributes

    Array attributes are singular attributes, but where the length is a
    variable multiple of a fixed size. When parsing, the payload is split up
    into chunks of that fixed size and returned as a list of individually
    parsed subelems. When building, each element is converted to the fixed
    sized and appended to form a blob.
    """
    names = ["array"]

    def __init__(self, subelem_schema, ids):
        self.subelem_schema = subelem_schema
        self.ids = ids
        if not hasattr(subelem_schema, "size"):
            raise ValueError("Can only build arrays of fixed-size elems "
                             "(schema object of type {} has no `size` attr)"
                             .format(type(subelem_schema).__name__))

    def build(self, attr_values):
        payload = b""
        for val in attr_values:
            payload += self.subelem_schema.build(val)
        return payload

    def parse(self, data):
        ret = []
        elem_size = self.subelem_schema.size
        while data:
            ret.append(self.subelem_schema.parse(data[:elem_size]))
            data = data[elem_size:]
        return ret

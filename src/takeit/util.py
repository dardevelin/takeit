# Originally from magic-wormhole (MIT, (c) 2015 Brian Warner).
# Lifted into takeit; see NOTICE for the full list.
# No unicode_literals
import json
import unicodedata
from binascii import hexlify, unhexlify

from attr import attrib, attrs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf import hkdf


def HKDF(skm, outlen, salt=None, CTXinfo=b""):
    """
    Return the RFC5869 'HMAC-based Key Derivation Function' result of
    using the given `salt`, tag from `CTXinfo` and secret from `skm`
    with a SHA256 hash.

    :param bytes skm: the input key material
    :param int outlen: output length, in bytes
    :param bytes salt: optional salt value (None for no salt)
    :param bytes CTXinfo: context / application-specific string (default is empty)

    :return bytes: the derived key material
    """
    return hkdf.HKDF(
        hashes.SHA256(),
        outlen,
        salt,
        CTXinfo,
    ).derive(skm)


def to_bytes(u):
    return unicodedata.normalize("NFC", u).encode("utf-8")


def to_unicode(any):
    if isinstance(any, str):
        return any
    return any.decode("ascii")


def bytes_to_hexstr(b):
    assert isinstance(b, bytes)
    hexstr = hexlify(b).decode("ascii")
    assert isinstance(hexstr, str)
    return hexstr


def hexstr_to_bytes(hexstr):
    assert isinstance(hexstr, str)
    b = unhexlify(hexstr.encode("ascii"))
    assert isinstance(b, bytes)
    return b


def dict_to_bytes(d):
    assert isinstance(d, dict)
    b = json.dumps(d).encode("utf-8")
    assert isinstance(b, bytes)
    return b


def bytes_to_dict(b):
    assert isinstance(b, bytes)
    d = json.loads(b.decode("utf-8"))
    assert isinstance(d, dict)
    return d


@attrs(repr=False, slots=True, hash=True)
class _ProvidesValidator:
    interface = attrib()

    def __call__(self, inst, attr, value):
        """
        We use a callable class to be able to change the ``__repr__``.
        """
        if not self.interface.providedBy(value):
            msg = "'{name}' must provide {interface!r} which {value!r} doesn't.".format(
                name=attr.name, interface=self.interface, value=value
            )
            raise TypeError(
                msg,
                attr,
                self.interface,
                value,
            )

    def __repr__(self):
        return f"<provides validator for interface {self.interface!r}>"


def provides(interface):
    """
    A validator that raises a `TypeError` if the initializer is called
    with an object that does not provide the requested *interface* (checks are
    performed using ``interface.providedBy(value)``.

    :param interface: The interface to check for.
    :type interface: ``zope.interface.Interface``

    :raises TypeError: With a human readable error message, the attribute
        (of type `attrs.Attribute`), the expected interface, and the
        value it got.
    """
    return _ProvidesValidator(interface)

# -*- coding: utf-8 -*-

"""
Framework agnostic PEM file parsing functions.
"""

from __future__ import absolute_import, division, print_function

import hashlib
import re

from ._compat import ABC, PY2, text_type


# mypy hack: Import typing information without actually importing anything.
MYPY = False
if MYPY:  # pragma: nocover
    from typing import List, Any, Union, AnyStr, Optional, Dict, Type  # noqa


class AbstractPEMObject(ABC):
    """
    Base class for parsed objects.
    """

    def __init__(self, pem_bytes):
        # type: (Union[text_type, bytes]) -> None
        if isinstance(pem_bytes, text_type):
            self._pem_bytes = pem_bytes.encode("ascii")  # type: bytes
        else:
            self._pem_bytes = pem_bytes
        self._sha1_hexdigest = None  # type: Optional[str]

    def __str__(self):
        # type: () -> str
        """
        Return the PEM-encoded content as a native :obj:`str`.
        """
        if not PY2:
            return self._pem_bytes.decode("ascii")
        return self._pem_bytes

    def __repr__(self):
        # type: () -> str
        return "<{0}(PEM string with SHA-1 digest {1!r})>".format(
            self.__class__.__name__, self.sha1_hexdigest
        )

    @property
    def sha1_hexdigest(self):
        # type: () -> str
        """
        A SHA-1 digest of the whole object for easy differentiation.

        .. versionadded:: 18.1.0
        """
        if self._sha1_hexdigest is None:
            self._sha1_hexdigest = hashlib.sha1(self._pem_bytes).hexdigest()

        return self._sha1_hexdigest

    def as_bytes(self):
        # type: () -> bytes
        """
        Return the PEM-encoded content as :obj:`bytes`.

        .. versionadded:: 16.1.0
        """
        return self._pem_bytes

    def as_text(self):
        # type: () -> text_type
        """
        Return the PEM-encoded content as Unicode text.

        .. versionadded:: 18.1.0
        """
        return self._pem_bytes.decode("utf-8")

    def __eq__(self, other):
        # type: (object) -> Union[NotImplemented, bool]
        if not isinstance(other, type(self)):
            return NotImplemented

        return (
            type(self) == type(other) and self._pem_bytes == other._pem_bytes
        )

    def __ne__(self, other):
        # type: (object) -> Union[NotImplemented, bool]
        if not isinstance(other, type(self)):
            return NotImplemented

        return type(self) != type(other) or self._pem_bytes != other._pem_bytes

    def __hash__(self):
        # type: () -> int
        return hash(self._pem_bytes)


class Certificate(AbstractPEMObject):
    """
    A certificate.
    """


class CertificateRequest(AbstractPEMObject):
    """
    A certificate signing request.

    .. versionadded:: 17.1.0
    """


class CertificateRevocationList(AbstractPEMObject):
    """
    A certificate revocation list.

    .. versionadded:: 18.2.0
    """


class Key(AbstractPEMObject):
    """
    A key of unknown type.
    """


class PrivateKey(Key):
    """
    A private key of unknown type.

    .. versionadded:: 19.1.0
    """


class PublicKey(Key):
    """
    A public key of unknown type.

    .. versionadded:: 19.1.0
    """


class RSAPrivateKey(PrivateKey):
    """
    A private RSA key.
    """


class RSAPublicKey(PublicKey):
    """
    A public RSA key.

    .. versionadded:: 19.1.0
    """


class ECPrivateKey(PrivateKey):
    """
    A private EC key.

    .. versionadded:: 19.2.0
    """


class DHParameters(AbstractPEMObject):
    """
    Diffie-Hellman parameters for DHE.
    """


class OpenSSHPrivateKey(PrivateKey):
    """
    OpenSSH private key format

    .. versionadded:: 19.3.0
    """


_PEM_TO_CLASS = {
    b"CERTIFICATE": Certificate,
    b"PRIVATE KEY": PrivateKey,
    b"PUBLIC KEY": PublicKey,
    b"ENCRYPTED PRIVATE KEY": PrivateKey,
    b"OPENSSH PRIVATE KEY": OpenSSHPrivateKey,
    b"RSA PRIVATE KEY": RSAPrivateKey,
    b"RSA PUBLIC KEY": RSAPublicKey,
    b"EC PRIVATE KEY": ECPrivateKey,
    b"DH PARAMETERS": DHParameters,
    b"NEW CERTIFICATE REQUEST": CertificateRequest,
    b"CERTIFICATE REQUEST": CertificateRequest,
    b"X509 CRL": CertificateRevocationList,
}  # type: Dict[bytes, Type[AbstractPEMObject]]

_PEM_RE = re.compile(
    b"-----BEGIN ("
    + b"|".join(_PEM_TO_CLASS.keys())
    + b""")-----\r?
.+?\r?
-----END \\1-----\r?\n?""",
    re.DOTALL,
)


def parse(pem_str):
    # type: (bytes) -> List[AbstractPEMObject]
    """
    Extract PEM objects from *pem_str*.

    :param pem_str: String to parse.
    :type pem_str: bytes
    :return: list of :ref:`pem-objects`
    """
    return [
        _PEM_TO_CLASS[match.group(1)](match.group(0))
        for match in _PEM_RE.finditer(pem_str)
    ]


def parse_file(file_name):
    # type: (str) -> List[AbstractPEMObject]
    """
    Read *file_name* and parse PEM objects from it using :func:`parse`.
    """
    with open(file_name, "rb") as f:
        return parse(f.read())

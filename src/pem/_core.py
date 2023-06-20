# SPDX-FileCopyrightText: 2013 Hynek Schlawack <hs@ox.cx>
#
# SPDX-License-Identifier: MIT

"""
Framework agnostic PEM file parsing functions.
"""

from __future__ import annotations

import hashlib
import re

from abc import ABCMeta
from base64 import b64decode
from functools import cached_property
from pathlib import Path


class AbstractPEMObject(metaclass=ABCMeta):
    """
    Base class for parsed objects.
    """

    _pem_bytes: bytes
    _sha1_hexdigest: str | None

    def __init__(self, pem_bytes: bytes | str):
        self._pem_bytes = (
            pem_bytes.encode("ascii")
            if isinstance(pem_bytes, str)
            else pem_bytes
        )

        self._sha1_hexdigest = None

    def __str__(self) -> str:
        """
        Return the PEM-encoded content as a native :obj:`str`.
        """
        return self._pem_bytes.decode("ascii")

    def __repr__(self) -> str:
        return "<{}(PEM string with SHA-1 digest {!r})>".format(
            self.__class__.__name__, self.sha1_hexdigest
        )

    @property
    def sha1_hexdigest(self) -> str:
        """
        A SHA-1 digest of the whole object for easy differentiation.

        .. versionadded:: 18.1.0
        .. versionchanged:: 20.1.0

           Carriage returns are removed before hashing to give the same hashes
           on Windows and UNIX-like operating systems.
        """
        if self._sha1_hexdigest is None:
            self._sha1_hexdigest = hashlib.sha1(  # noqa[S324]
                self._pem_bytes.replace(b"\r", b"")
            ).hexdigest()

        return self._sha1_hexdigest

    def as_bytes(self) -> bytes:
        """
        Return the PEM-encoded content as :obj:`bytes`.

        .. versionadded:: 16.1.0
        """
        return self._pem_bytes

    def as_text(self) -> str:
        """
        Return the PEM-encoded content as text.

        .. versionadded:: 18.1.0
        """
        return self._pem_bytes.decode("utf-8")

    @cached_property
    def _extracted_payload(self) -> bytes:
        """
        Lazily extract the payload from the stored PEM.
        """
        return b"".join(
            line
            for line in self._pem_bytes.splitlines()[1:-1]
            if b":" not in line  # remove headers
        )

    def payload_as_bytes(self) -> bytes:
        """
        Return the payload of the PEM-encoded content as :obj:`bytes`.

        Possible PEM headers are removed.

        .. versionadded:: 23.1.0
        """
        return self._extracted_payload

    def payload_as_text(self) -> str:
        """
        Return the payload of the PEM-encoded content as Unicode text.

        Possible PEM headers are removed.

        .. versionadded:: 23.1.0
        """
        return self._extracted_payload.decode("utf-8")

    def payload_decoded(self) -> bytes:
        """
        Return the decoded payload of the PEM-encoded content as :obj:`bytes`.

        Possible PEM headers are removed.

        .. versionadded:: 23.1.0
        """
        return b64decode(self._extracted_payload)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented

        return (
            type(self) == type(other) and self._pem_bytes == other._pem_bytes
        )

    def __hash__(self) -> int:
        return hash(self._pem_bytes)


class Certificate(AbstractPEMObject):
    """
    A certificate.
    """


class OpenSSLTrustedCertificate(Certificate):
    """
    An OpenSSL "trusted certificate".

    .. versionadded:: 21.2.0
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


class DSAPrivateKey(PrivateKey):
    """
    A private DSA key.

    Also private DSA key in OpenSSH legacy PEM format.

    .. versionadded:: 21.1.0
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


class SSHPublicKey(PublicKey):
    """
    A public key in SSH :rfc:`4716` format.

    The Secure Shell (SSH) Public Key File Format.

    .. versionadded:: 21.1.0
    """


class SSHCOMPrivateKey(PrivateKey):
    """
    A private key in SSH.COM / Tectia format.

    .. versionadded:: 21.1.0
    """


class OpenPGPPublicKey(PublicKey):
    """
    An :rfc:`4880` armored OpenPGP public key.

    .. versionadded:: 23.1.0
    """


class OpenPGPPrivateKey(PrivateKey):
    """
    An :rfc:`4880` armored OpenPGP private key.

    .. versionadded:: 23.1.0
    """


_PEM_TO_CLASS: dict[bytes, type[AbstractPEMObject]] = {
    b"CERTIFICATE": Certificate,
    b"TRUSTED CERTIFICATE": OpenSSLTrustedCertificate,
    b"PRIVATE KEY": PrivateKey,
    b"PUBLIC KEY": PublicKey,
    b"ENCRYPTED PRIVATE KEY": PrivateKey,
    b"OPENSSH PRIVATE KEY": OpenSSHPrivateKey,
    b"DSA PRIVATE KEY": DSAPrivateKey,
    b"RSA PRIVATE KEY": RSAPrivateKey,
    b"RSA PUBLIC KEY": RSAPublicKey,
    b"EC PRIVATE KEY": ECPrivateKey,
    b"DH PARAMETERS": DHParameters,
    b"NEW CERTIFICATE REQUEST": CertificateRequest,
    b"CERTIFICATE REQUEST": CertificateRequest,
    b"SSH2 PUBLIC KEY": SSHPublicKey,
    b"SSH2 ENCRYPTED PRIVATE KEY": SSHCOMPrivateKey,
    b"X509 CRL": CertificateRevocationList,
    b"PGP PUBLIC KEY BLOCK": OpenPGPPublicKey,
    b"PGP PRIVATE KEY BLOCK": OpenPGPPrivateKey,
}

# See https://tools.ietf.org/html/rfc1421
# and https://tools.ietf.org/html/rfc4716 for space instead of fifth dash.
_PEM_RE = re.compile(
    b"----[- ]BEGIN ("
    + b"|".join(_PEM_TO_CLASS.keys())
    + b""")[- ]----\r?
(?P<payload>.+?)\r?
----[- ]END \\1[- ]----\r?\n?""",
    re.DOTALL,
)


def parse(pem_str: bytes) -> list[AbstractPEMObject]:
    """
    Extract PEM-like objects from *pem_str*.

    :param pem_str: String to parse.
    :return: list of :ref:`pem-objects`
    """
    return [
        _PEM_TO_CLASS[match.group(1)](match.group(0))
        for match in _PEM_RE.finditer(pem_str)
    ]


def parse_file(file_name: str | Path) -> list[AbstractPEMObject]:
    """
    Read *file_name* and parse PEM objects from it using :func:`parse`.
    """
    return parse(Path(file_name).read_bytes())

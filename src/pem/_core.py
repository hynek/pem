# -*- coding: utf-8 -*-

"""
Framework agnostic PEM file parsing functions.
"""

from __future__ import absolute_import, division, print_function

import hashlib
import re

from ._compat import PY3, unicode


class _Base(object):
    """
    Base class for parsed objects.
    """
    def __init__(self, _pem_bytes):
        if isinstance(_pem_bytes, unicode):
            _pem_bytes = _pem_bytes.encode('ascii')
        self._pem_bytes = _pem_bytes

    if PY3:
        def __str__(self):
            return self._pem_bytes.decode('ascii')
    else:
        def __str__(self):
            return self._pem_bytes

    def __repr__(self):
        return '<{0}(PEM string with SHA-1 digest {1!r})>'.format(
            self.__class__.__name__,
            hashlib.sha1(self._pem_bytes).hexdigest()
        )

    def as_bytes(self):
        """
        Return the PEM-encoded content as :obj:`bytes`.
        """
        return self._pem_bytes

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return (type(self) == type(other) and
                self._pem_bytes == other._pem_bytes)

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return (type(self) != type(other) or
                self._pem_bytes != other._pem_bytes)

    def __hash__(self):
        return hash(self._pem_bytes)


class Certificate(_Base):
    """
    A certificate.
    """


class CertificateRequest(_Base):
    """
    A certificate signing request.
    """


class Key(_Base):
    """
    A secret key of unknown type.
    """


class RSAPrivateKey(Key):
    """
    A secret RSA key.
    """


class DHParameters(_Base):
    """
    Diffie-Hellman parameters for DHE.
    """


_PEM_TO_CLASS = {
    b"CERTIFICATE": Certificate,
    b"PRIVATE KEY": Key,
    b"RSA PRIVATE KEY": RSAPrivateKey,
    b"DH PARAMETERS": DHParameters,
    b"NEW CERTIFICATE REQUEST": CertificateRequest,
    b"CERTIFICATE REQUEST": CertificateRequest,
}
_PEM_RE = re.compile(
    b"-----BEGIN (" + b"|".join(_PEM_TO_CLASS.keys()) + b""")-----\r?
.+?\r?
-----END \\1-----\r?\n?""", re.DOTALL)


def parse(pem_str):
    """
    Extract PEM objects from *pem_str*.

    :param pem_str: String to parse.
    :type pem_str: bytes
    :return: list of :ref:`pem-objects`
    """
    return [_PEM_TO_CLASS[match.group(1)](match.group(0))
            for match in _PEM_RE.finditer(pem_str)]


def parse_file(file_name):
    """
    Read *file_name* and parse PEM objects from it using :func:`parse`.
    """
    with open(file_name, 'rb') as f:
        return parse(f.read())

# -*- coding: utf-8 -*-

"""
Framework agnostic PEM file parsing functions.
"""

from __future__ import absolute_import, division, print_function

import codecs
import re


class _Base(object):
    """
    Base class for parsed objects.
    """
    def __init__(self, _pem_str):
        self.pem_str = _pem_str

    def __str__(self):
        return self.pem_str

    def __repr__(self):
        return '<{0}(pem_str={1!r})>'.format(
            self.__class__.__name__, self.pem_str
        )


class Certificate(_Base):
    """
    A certificate.
    """


class Key(_Base):
    """
    A secret key.
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
    'CERTIFICATE': Certificate,
    'RSA PRIVATE KEY': RSAPrivateKey,
    'DH PARAMETERS': DHParameters,
}
_PEM_RE = re.compile(u"""-----BEGIN ({0})-----\r?
.+?\r?
-----END \\1-----\r?\n?""".format('|'.join(_PEM_TO_CLASS.keys())), re.DOTALL)


def parse(pem_str):
    """
    Extract PEM objects from *pem_str*.
    """
    return [_PEM_TO_CLASS[match.group(1)](match.group(0))
            for match in _PEM_RE.finditer(pem_str)]


def parse_file(file_name):
    """
    Read *file_name* and parse PEM objects from it.
    """
    with codecs.open(file_name, 'rb', encoding='utf-8', errors='ignore') as f:
        return parse(f.read())

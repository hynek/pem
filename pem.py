from __future__ import absolute_import, division, print_function

import codecs
import re


__version__ = '0.2.0'
__author__ = 'Hynek Schlawack'
__license__ = 'MIT'
__copyright__ = 'Copyright 2014 Hynek Schlawack'


class _Base(object):
    def __init__(self, _pem_str):
        self.pem_str = _pem_str

    def __str__(self):
        return self.pem_str

    def __repr__(self):
        return '<{0}(pem_str={1!r})>'.format(
            self.__class__.__name__, self.pem_str
        )


class Certificate(_Base):
    pass


class Key(_Base):
    pass


class RSAPrivateKey(Key):
    pass


_PEM_TO_CLASS = {
    'CERTIFICATE': Certificate,
    'RSA PRIVATE KEY': RSAPrivateKey,
}
_PEM_RE = re.compile(u"""-----BEGIN ({0})-----
.+?
-----END \\1-----
""".format('|'.join(_PEM_TO_CLASS.keys())), re.DOTALL)


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
    with codecs.open(file_name, 'rb', encoding='ascii') as f:
        return parse(f.read())


def certificateOptionsFromFiles(*pemFiles, **kw):
    """
    Read all *pemFiles*, find one key, use the first certificate as server
    certificate and the rest as chain.
    """
    from twisted.internet import ssl

    pems = []
    for pemFile in pemFiles:
        pems += parse_file(pemFile)
    keys = [key for key in pems if isinstance(key, Key)]
    if not len(keys):
        raise ValueError('Supplied PEM file(s) do *not* contain a key.')
    if len(keys) > 1:
        raise ValueError('Supplied PEM file(s) contain *more* than one key.')
    certs = [cert for cert in pems if isinstance(cert, Certificate)]
    if not len(certs):
        raise ValueError('*At least one* certificate is required.')
    cert = ssl.PrivateCertificate.loadPEM(str(keys[0]) + str(certs[0]))
    chain = [ssl.Certificate.loadPEM(str(certPEM)).original
             for certPEM in certs[1:]]

    return ssl.CertificateOptions(
        privateKey=cert.privateKey.original,
        certificate=cert.original,
        extraCertChain=chain,
        **kw
    )

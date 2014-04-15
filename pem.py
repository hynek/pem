from __future__ import absolute_import, division, print_function

import codecs
import re


__version__ = '0.3.0'
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


class DHParameters(_Base):
    pass


_PEM_TO_CLASS = {
    'CERTIFICATE': Certificate,
    'RSA PRIVATE KEY': RSAPrivateKey,
    'DH PARAMETERS': DHParameters,
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
    with codecs.open(file_name, 'rb', encoding='utf-8', errors='ignore') as f:
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

    fakeEDHSupport = "dhParameters" in kw and not _DH_PARAMETERS_SUPPORTED
    if fakeEDHSupport:
        dhParameters = kw.pop("dhParameters")

    ctxFactory = ssl.CertificateOptions(
        privateKey=cert.privateKey.original,
        certificate=cert.original,
        extraCertChain=chain,
        **kw)

    if fakeEDHSupport:
        return _DHParamContextFactory(ctxFactory, dhParameters)
    else:
        return ctxFactory


class _DHParamContextFactory(object):
    """
    A wrapping context factory that gets a context from a different
    context factory and then sets temporary DH params on it. This
    enables PFS ciphersuites using DHE.
    """
    def __init__(self, ctxFactory, dhParameters):
        self.ctxFactory = ctxFactory
        self.dhParameters = dhParameters

    def getContext(self):
        ctx = self.ctxFactory.getContext()
        ctx.load_tmp_dh(self.dhParameters._dhFile.path)
        return ctx


class _DiffieHellmanParameters(object):
    """
    A representation of key generation parameters that are required for
    Diffie-Hellman key exchange.
    """
    def __init__(self, parameters):
        self._dhFile = parameters

    @classmethod
    def fromFile(cls, filePath):
        """
        Load parameters from a file.

        Such a file can be generated using the C{openssl} command line tool as
        following:

        C{openssl dhparam -out dh_param_1024.pem -2 1024}

        Please refer to U{OpenSSL's C{dhparam} documentation
        <http://www.openssl.org/docs/apps/dhparam.html>} for further details.

        @param filePath: A file containing parameters for Diffie-Hellman key
            exchange.
        @type filePath: L{FilePath <twisted.python.filepath.FilePath>}

        @return: A instance that loads its parameters from C{filePath}.
        @rtype: L{DiffieHellmanParameters
            <twisted.internet.ssl.DiffieHellmanParameters>}
        """
        return cls(filePath)


try:  # pragma: nocover
    from twisted.internet.ssl import DiffieHellmanParameters
    _DH_PARAMETERS_SUPPORTED = True
except ImportError:
    DiffieHellmanParameters = _DiffieHellmanParameters
    _DH_PARAMETERS_SUPPORTED = False

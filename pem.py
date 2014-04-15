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


def certificateOptionsFromPEMs(pemObjects, **kw):
    """
    Load a CertificateOptions from the given collection of PEM objects
    (already-loaded private keys and certificates).
    """
    from OpenSSL.SSL import FILETYPE_PEM
    from twisted.internet import ssl

    keys = [key for key in pemObjects if isinstance(key, Key)]
    if not len(keys):
        raise ValueError('Supplied PEM file(s) does *not* contain a key.')
    if len(keys) > 1:
        raise ValueError('Supplied PEM file(s) contains *more* than one key.')

    privateKey = ssl.KeyPair.load(keys[0].pem_str, FILETYPE_PEM)

    certs = [cert for cert in pemObjects if isinstance(cert, Certificate)]
    if not len(certs):
        raise ValueError('*At least one* certificate is required.')
    certificates = [ssl.Certificate.loadPEM(str(certPEM))
                    for certPEM in certs]

    certificatesByFingerprint = dict(
        [(certificate.getPublicKey().keyHash(), certificate)
         for certificate in certificates]
    )

    if privateKey.keyHash() not in certificatesByFingerprint:
        raise ValueError("No certificate matching %s found")

    primaryCertificate = certificatesByFingerprint.pop(privateKey.keyHash())

    fakeEDHSupport = "dhParameters" in kw and not _DH_PARAMETERS_SUPPORTED
    if fakeEDHSupport:
        dhParameters = kw.pop("dhParameters")

    ctxFactory = ssl.CertificateOptions(
        privateKey=privateKey.original,
        certificate=primaryCertificate.original,
        extraCertChain=[chain.original
                        for chain in certificatesByFingerprint.values()],
        **kw
    )

    if fakeEDHSupport:
        return _DHParamContextFactory(ctxFactory, dhParameters)
    else:
        return ctxFactory


def certificateOptionsFromFiles(*pemFiles, **kw):
    """
    Read all files named by *pemFiles*, and return a Twisted CertificateOptions
    which can be used to run a TLS server.

    In those PEM files, identify one private key and its corresponding
    certificate to use as the primary certificate, then use the rest of the
    certificates found as chain certificates.  Raise a ValueError if no
    certificate matching a private key is found.
    """
    pems = []
    for pemFile in pemFiles:
        pems += parse_file(pemFile)
    return certificateOptionsFromPEMs(pems, **kw)


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

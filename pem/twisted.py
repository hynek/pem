# -*- coding: utf-8 -*-

"""
Twisted-specific convenience helpers.
"""

from __future__ import absolute_import, division, print_function

from ._core import parse_file, Certificate, Key


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
        raise ValueError("No certificate matching {fingerprint} found.".format(
            fingerprint=privateKey.keyHash()
        ))

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


try:
    from twisted.internet.ssl import DiffieHellmanParameters
    _DH_PARAMETERS_SUPPORTED = True
except ImportError:  # pragma: nocover
    DiffieHellmanParameters = _DiffieHellmanParameters
    _DH_PARAMETERS_SUPPORTED = False

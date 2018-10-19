# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

import pytest

from OpenSSL import crypto
from pretend import call, call_recorder, stub
from twisted.internet import ssl

import pem

from pem.twisted import certificateOptionsFromFiles

from .data import CERT_PEMS, DH_PEM, KEY_PEM, KEY_PEM2


@pytest.fixture
def keyCertChainDHFile(tmpdir):
    """
    Returns a file containing the key, three certificates, and DH parameters.
    """
    pemFile = tmpdir.join("key_cert_and_chain_and_params.pem")
    pemFile.write(KEY_PEM + b"".join(CERT_PEMS) + DH_PEM)

    return pemFile


@pytest.fixture
def keyCertChainFile(tmpdir):
    """
    Returns a file containing the key and three certificates.
    """
    pemFile = tmpdir.join("key_cert_and_chain.pem")
    pemFile.write(KEY_PEM + b"".join(CERT_PEMS))

    return pemFile


class TestCertificateOptionsFromFiles(object):
    def test_worksWithoutChain(self, tmpdir):
        """
        Creating CO without chain certificates works.
        """
        keyFile = tmpdir.join("key.pem")
        keyFile.write(KEY_PEM)
        certFile = tmpdir.join("cert.pem")
        certFile.write(CERT_PEMS[0])

        ctxFactory = certificateOptionsFromFiles(str(keyFile), str(certFile))

        assert [] == ctxFactory.extraCertChain

    def test_worksWithChainInExtraFile(self, tmpdir):
        """
        Chain can be in a separate file.
        """
        keyFile = tmpdir.join("key.pem")
        keyFile.write(KEY_PEM)
        certFile = tmpdir.join("cert.pem")
        certFile.write(CERT_PEMS[0])
        chainFile = tmpdir.join("chain.pem")
        chainFile.write(b"".join(CERT_PEMS[1:]))

        ctxFactory = certificateOptionsFromFiles(
            str(keyFile), str(certFile), str(chainFile)
        )

        assert 2 == len(ctxFactory.extraCertChain)

    def test_worksWithChainInSameFile(self, tmpdir):
        """
        Chain can be in the same file as the certificate.
        """
        keyFile = tmpdir.join("key.pem")
        keyFile.write(KEY_PEM)
        certFile = tmpdir.join("cert_and_chain.pem")
        certFile.write(b"".join(CERT_PEMS))

        ctxFactory = certificateOptionsFromFiles(str(keyFile), str(certFile))

        assert 2 == len(ctxFactory.extraCertChain)

    def test_useTypesNotOrdering(self, tmpdir):
        """
        L{pem.certificateOptionsFromFiles} identifies the chain, key, and
        certificate for Twisted's L{CertificateOptions} based on their types
        and certificate fingerprints, not their order within the file.
        """
        keyFile = tmpdir.join("key.pem")
        keyFile.write(KEY_PEM)
        certFile = tmpdir.join("cert_and_chain.pem")
        certFile.write(b"".join(reversed(CERT_PEMS)))

        ctxFactory = certificateOptionsFromFiles(str(keyFile), str(certFile))

        assert 2 == len(ctxFactory.extraCertChain)

    def test_worksWithEverythingInOneFile(self, keyCertChainDHFile):
        """
        Key, certificate, and chain can also be in a single file.
        """
        ctxFactory = certificateOptionsFromFiles(str(keyCertChainDHFile))

        assert 2 == len(ctxFactory.extraCertChain)
        assert ctxFactory.dhParameters is not None

    def test_passesCertsInCorrectFormat(self, keyCertChainDHFile):
        """
        PEM objects are correctly detected and passed into CO.
        """
        ctxFactory = certificateOptionsFromFiles(str(keyCertChainDHFile))

        assert isinstance(ctxFactory.privateKey, crypto.PKey)
        assert isinstance(ctxFactory.certificate, crypto.X509)
        assert all(
            isinstance(cert, crypto.X509) for cert in ctxFactory.extraCertChain
        )

    def test_forwardsKWargs(self, keyCertChainDHFile):
        """
        Extra keyword arguments are passed into CO.
        """
        ctxFactory = certificateOptionsFromFiles(
            str(keyCertChainDHFile), fixBrokenPeers=True
        )

        assert True is ctxFactory.fixBrokenPeers

    def test_catchesMissingKey(self, tmpdir):
        """
        Raises ValueError if a key is missing.
        """
        certFile = tmpdir.join("cert_and_chain.pem")
        certFile.write(b"".join(CERT_PEMS))

        with pytest.raises(ValueError):
            certificateOptionsFromFiles(str(certFile))

    def test_catchesMultipleKeys(self, tmpdir):
        """
        Raises ValueError if multiple keys are present.
        """
        allFile = tmpdir.join("key_cert_and_chain.pem")
        allFile.write(KEY_PEM + b"".join(CERT_PEMS) + KEY_PEM2)

        with pytest.raises(ValueError):
            certificateOptionsFromFiles(str(allFile))

    def test_catchesMissingCertificate(self, tmpdir):
        """
        Raises ValueError if no certificate is passed.
        """
        keyFile = tmpdir.join("key.pem")
        keyFile.write(KEY_PEM)

        with pytest.raises(ValueError):
            certificateOptionsFromFiles(str(keyFile))

    def test_catchesKeyCertificateMismatch(self, tmpdir):
        """
        A ValueError is raised when some certificates are present in the pem,
        but no certificate in the pem matches the key.
        """
        keyFile = tmpdir.join("key.pem")
        keyFile.write(KEY_PEM + b"".join(CERT_PEMS[1:]))

        with pytest.raises(ValueError) as excinfo:
            certificateOptionsFromFiles(str(keyFile))

        assert str(excinfo.value).startswith("No certificate matching ")

    def test_catchesMultipleDHParams(self, tmpdir):
        """
        A ValueError is raised when more than one set of DH parameters is
        present.
        """
        pemFile = tmpdir.join("multiple_params.pem")
        pemFile.write(KEY_PEM + CERT_PEMS[0] + DH_PEM + DH_PEM)

        with pytest.raises(ValueError) as excinfo:
            certificateOptionsFromFiles(str(pemFile))

        assert (
            "Supplied PEM file(s) contain(s) *more* than one set of DH "
            "parameters."
        ) == str(excinfo.value)

    def test_removedLegacyDHParameterSupport(self, keyCertChainFile):
        """
        Passing dhParameters as an argument raises a TypeError.
        """
        fakeParameters = object()

        with pytest.raises(TypeError, match="Passing DH parameters"):
            certificateOptionsFromFiles(
                str(keyCertChainFile), dhParameters=fakeParameters
            )


class _TestForwardCompatibleDHE(object):
    def test_realDHParameterFileSupport(self, monkeypatch, keyCertChainDHFile):
        """
        Pass DH parameters loaded from a file directly to CertificateOptions if
        the installed version of Twisted supports it.
        """
        fakeCtxFactory = object()
        recorder = call_recorder(lambda *a, **kw: fakeCtxFactory)
        monkeypatch.setattr(ssl, "CertificateOptions", recorder)
        monkeypatch.setattr(pem.twisted, "_DH_PARAMETERS_SUPPORTED", True)

        ctxFactory = certificateOptionsFromFiles(str(keyCertChainDHFile))

        assert ctxFactory is fakeCtxFactory
        assert isinstance(
            recorder.calls[0].kwargs["dhParameters"],
            pem.twisted.DiffieHellmanParameters,
        )

    def test_DHParamContextFactory(self):
        """
        ContextFactory is wrapped and DH params loaded.
        """
        fakeContext = stub(load_tmp_dh=call_recorder(lambda dhParams: None))
        fakeFactory = stub(getContext=lambda: fakeContext)
        fakeDH = stub(path=b"foo")

        ctxFactory = pem.twisted._DHParamContextFactory(
            fakeFactory, pem.twisted._DiffieHellmanParameters(fakeDH)
        )
        ctx = ctxFactory.getContext()

        assert fakeContext is ctx
        assert [call(b"foo")] == fakeContext.load_tmp_dh.calls

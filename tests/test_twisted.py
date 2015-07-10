# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function


import pytest

from OpenSSL import crypto, SSL
from pretend import call, call_recorder, stub
from twisted.internet import ssl

import pem

from pem.twisted import certificateOptionsFromFiles

from .data import KEY_PEM, KEY_PEM2, CERT_PEMS


@pytest.fixture
def allFile(tmpdir):
    """
    Returns a file containing the key and three certificates.
    """
    allFile = tmpdir.join('key_cert_and_chain.pem')
    allFile.write(KEY_PEM + ''.join(CERT_PEMS))
    return allFile


class TestCertificateOptionsFromFiles(object):
    def test_worksWithoutChain(self, tmpdir):
        """
        Creating CO without chain certificates works.
        """
        keyFile = tmpdir.join('key.pem')
        keyFile.write(KEY_PEM)
        certFile = tmpdir.join('cert.pem')
        certFile.write(CERT_PEMS[0])
        ctxFactory = certificateOptionsFromFiles(
            str(keyFile), str(certFile),
        )
        assert [] == ctxFactory.extraCertChain

    def test_worksWithChainInExtraFile(self, tmpdir):
        """
        Chain can be in a seperate file.
        """
        keyFile = tmpdir.join('key.pem')
        keyFile.write(KEY_PEM)
        certFile = tmpdir.join('cert.pem')
        certFile.write(CERT_PEMS[0])
        chainFile = tmpdir.join('chain.pem')
        chainFile.write(''.join(CERT_PEMS[1:]))
        ctxFactory = certificateOptionsFromFiles(
            str(keyFile), str(certFile), str(chainFile)
        )
        assert 2 == len(ctxFactory.extraCertChain)

    def test_worksWithChainInSameFile(self, tmpdir):
        """
        Chain can be in the same file as the certificate.
        """
        keyFile = tmpdir.join('key.pem')
        keyFile.write(KEY_PEM)
        certFile = tmpdir.join('cert_and_chain.pem')
        certFile.write(''.join(CERT_PEMS))
        ctxFactory = certificateOptionsFromFiles(
            str(keyFile), str(certFile)
        )
        assert 2 == len(ctxFactory.extraCertChain)

    def test_useTypesNotOrdering(self, tmpdir):
        """
        L{pem.certificateOptionsFromFiles} identifies the chain, key, and
        certificate for Twisted's L{CertificateOptions} based on their types
        and certificate fingerprints, not their order within the file.
        """
        keyFile = tmpdir.join('key.pem')
        keyFile.write(KEY_PEM)
        certFile = tmpdir.join('cert_and_chain.pem')
        certFile.write(''.join(reversed(CERT_PEMS)))
        ctxFactory = certificateOptionsFromFiles(
            str(keyFile), str(certFile)
        )
        assert 2 == len(ctxFactory.extraCertChain)

    def test_worksWithEverythingInOneFile(self, allFile):
        """
        Key, certificate, and chain can also be in a single file.
        """
        ctxFactory = certificateOptionsFromFiles(str(allFile))
        assert 2 == len(ctxFactory.extraCertChain)

    def test_passesCertsInCorrectFormat(self, allFile):
        """
        PEM objects are correctly detected and passed into CO.
        """
        ctxFactory = certificateOptionsFromFiles(str(allFile))
        assert isinstance(ctxFactory.privateKey, crypto.PKey)
        assert isinstance(ctxFactory.certificate, crypto.X509)
        assert all(isinstance(cert, crypto.X509)
                   for cert in ctxFactory.extraCertChain)

    def test_forwardsKWargs(self, allFile):
        """
        Extra keyword arguments are passed into CO.
        """
        ctxFactory = certificateOptionsFromFiles(
            str(allFile),
            method=SSL.TLSv1_METHOD,
        )
        assert SSL.TLSv1_METHOD is ctxFactory.method

    def test_catchesMissingKey(self, tmpdir):
        """
        Raises ValueError if a key is missing.
        """
        certFile = tmpdir.join('cert_and_chain.pem')
        certFile.write(''.join(CERT_PEMS))
        with pytest.raises(ValueError):
            certificateOptionsFromFiles(
                str(certFile)
            )

    def test_catchesMultipleKeys(self, tmpdir):
        """
        Raises ValueError if multiple keys are present.
        """
        allFile = tmpdir.join('key_cert_and_chain.pem')
        allFile.write(KEY_PEM + ''.join(CERT_PEMS) + KEY_PEM2)
        with pytest.raises(ValueError):
            certificateOptionsFromFiles(
                str(allFile)
            )

    def test_catchesMissingCertificate(self, tmpdir):
        """
        Raises ValueError if no certificate is passed.
        """
        keyFile = tmpdir.join('key.pem')
        keyFile.write(KEY_PEM)
        with pytest.raises(ValueError):
            certificateOptionsFromFiles(
                str(keyFile)
            )

    def test_catchesKeyCertificateMismatch(self, tmpdir):
        """
        A ValueError is raised when some certificates are present in the pem,
        but no certificate in the pem matches the key.
        """
        keyFile = tmpdir.join('key.pem')
        keyFile.write(KEY_PEM + "".join(CERT_PEMS[1:]))
        with pytest.raises(ValueError) as excinfo:
            certificateOptionsFromFiles(
                str(keyFile)
            )
        assert str(excinfo.value).startswith("No certificate matching ")


class TestForwardCompatibleDHE(object):
    def test_fakeDHParameterSupport(self, monkeypatch, allFile, recwarn):
        """
        Fake DH parameter support if Twisted doesn't support it.

        Warns about deprecation.
        """
        fakeCtxFactory = object()
        recorder = call_recorder(lambda *a, **kw: fakeCtxFactory)
        monkeypatch.setattr(ssl, "CertificateOptions", recorder)
        monkeypatch.setattr(pem.twisted, "_DH_PARAMETERS_SUPPORTED", False)

        fakeParameters = object()
        ctxFactory = certificateOptionsFromFiles(
            str(allFile),
            dhParameters=fakeParameters
        )

        assert isinstance(ctxFactory, pem.twisted._DHParamContextFactory)
        assert ctxFactory.ctxFactory is fakeCtxFactory
        assert "dhParameters" not in recorder.calls[0].kwargs

        w = recwarn.pop(DeprecationWarning)
        assert (
            "The backport of DiffieHellmanParameters will be removed."
            in str(w.message)
        )

    def test_realDHParameterSupport(self, monkeypatch, allFile):
        """
        Pass DH parameters directly to CertificateOptions if the installed
        version of Twisted supports it.
        """
        fakeCtxFactory = object()
        recorder = call_recorder(lambda *a, **kw: fakeCtxFactory)
        monkeypatch.setattr(ssl, "CertificateOptions", recorder)
        monkeypatch.setattr(pem.twisted, "_DH_PARAMETERS_SUPPORTED", True)

        fakeParameters = object()
        ctxFactory = certificateOptionsFromFiles(
            str(allFile),
            dhParameters=fakeParameters
        )

        assert ctxFactory is fakeCtxFactory
        assert recorder.calls[0].kwargs["dhParameters"] == fakeParameters

    def test_DiffieHellmanParameters(self):
        """
        Make sure lines are executed.
        """
        o = object()
        dhp = pem.twisted._DiffieHellmanParameters.fromFile(o)
        assert o is dhp._dhFile

    def test_DHParamContextFactory(self):
        """
        ContextFactory is wrapped and DH params loaded.
        """
        fakeContext = stub(
            load_tmp_dh=call_recorder(lambda dhParams: None)
        )
        fakeFactory = stub(getContext=lambda: fakeContext)
        fakeDH = stub(path=b"foo")
        ctxFactory = pem.twisted._DHParamContextFactory(
            fakeFactory, pem.twisted._DiffieHellmanParameters(fakeDH)
        )
        ctx = ctxFactory.getContext()
        assert fakeContext is ctx
        assert [call(b"foo")] == fakeContext.load_tmp_dh.calls


class TestDeprecations(object):
    def test_certificateOptionsFromFiles(self, monkeypatch, recwarn):
        """
        pem.certificateOptionsFromFiles raises a deprecation warning and calls
        the original method with the same arguments.
        """
        cr = call_recorder(lambda *a, **kw: None)
        monkeypatch.setattr(pem, "certificateOptionsFromFilesOriginal", cr)
        pem.certificateOptionsFromFiles("foo", bar="baz")
        assert [call("foo", bar="baz")] == cr.calls
        w = recwarn.pop(DeprecationWarning)
        assert "certificateOptionsFromFiles" in str(w.message)

    def test_certificateOptionsFromPEMs(self, monkeypatch, recwarn):
        """
        pem.certificateOptionsFromPEMs raises a deprecation warning and calls
        the original method with the same arguments.
        """
        cr = call_recorder(lambda *a, **kw: None)
        monkeypatch.setattr(pem, "certificateOptionsFromPEMsOriginal", cr)
        pem.certificateOptionsFromPEMs("foo", bar="baz")
        assert [call("foo", bar="baz")] == cr.calls
        w = recwarn.pop(DeprecationWarning)
        assert "certificateOptionsFromPEMs" in str(w.message)

# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)

import pytest

import pem


def test_certificate_has_correct_repr():
    cert = pem.Certificate('test')
    assert "<Certificate(pem_str='test')>" == repr(cert)


def test_key_has_correct_repr():
    key = pem.RSAPrivateKey('test')
    assert "<RSAPrivateKey(pem_str='test')>" == repr(key)


def test_parse_key():
    keys = pem.parse(KEY_PEM)
    assert 1 == len(keys)
    key = keys[0]
    assert isinstance(key, pem.RSAPrivateKey)
    assert KEY_PEM == str(key)


def test_parse_certificates():
    certs = pem.parse(''.join(CERT_PEMS))
    assert CERT_PEMS == [str(cert) for cert in certs]


def test_parse_file(tmpdir):
    certs_file = tmpdir.join('certs.pem')
    certs_file.write(''.join(CERT_PEMS))
    certs = pem.parse_file(str(certs_file))
    assert CERT_PEMS == [str(cert) for cert in certs]


def test_certificateOptionsFromFilesWorksWithoutChain(tmpdir):
    pytest.importorskip('twisted')
    keyFile = tmpdir.join('key.pem')
    keyFile.write(KEY_PEM)
    certFile = tmpdir.join('cert.pem')
    certFile.write(CERT_PEMS[0])
    ctxFactory = pem.certificateOptionsFromFiles(
        str(keyFile), str(certFile),
    )
    assert [] == ctxFactory.extraCertChain


def test_certificateOptionsFromFilesWorksWithChainInExtraFile(tmpdir):
    pytest.importorskip('twisted')
    keyFile = tmpdir.join('key.pem')
    keyFile.write(KEY_PEM)
    certFile = tmpdir.join('cert.pem')
    certFile.write(CERT_PEMS[0])
    chainFile = tmpdir.join('chain.pem')
    chainFile.write(''.join(CERT_PEMS[1:]))
    ctxFactory = pem.certificateOptionsFromFiles(
        str(keyFile), str(certFile), str(chainFile)
    )
    assert 2 == len(ctxFactory.extraCertChain)


def test_certificateOptionsFromFilesWorksWithChainInSameFile(tmpdir):
    pytest.importorskip('twisted')
    keyFile = tmpdir.join('key.pem')
    keyFile.write(KEY_PEM)
    certFile = tmpdir.join('cert_and_chain.pem')
    certFile.write(''.join(CERT_PEMS))
    ctxFactory = pem.certificateOptionsFromFiles(str(keyFile), str(certFile))
    assert 2 == len(ctxFactory.extraCertChain)


@pytest.fixture
def allFile(tmpdir):
    """
    Returns a file containing the key and three certificates.
    """
    allFile = tmpdir.join('key_cert_and_chain.pem')
    allFile.write(KEY_PEM + ''.join(CERT_PEMS))
    return allFile


def test_certificateOptionsFromFilesWorksWithEverythingInOneFile(allFile):
    pytest.importorskip('twisted')
    ctxFactory = pem.certificateOptionsFromFiles(str(allFile))
    assert 2 == len(ctxFactory.extraCertChain)


def test_certificateOptionsFromFilesPassesCertsInCorrectFormat(allFile):
    pytest.importorskip('twisted')
    crypto = pytest.importorskip('OpenSSL.crypto')
    ctxFactory = pem.certificateOptionsFromFiles(str(allFile))
    assert isinstance(ctxFactory.privateKey, crypto.PKey)
    assert isinstance(ctxFactory.certificate, crypto.X509)
    assert all(isinstance(cert, crypto.X509)
               for cert in ctxFactory.extraCertChain)


def test_certificateOptionsForwardsKWargs(allFile):
    pytest.importorskip('twisted')
    ssl = pytest.importorskip('OpenSSL.SSL')
    ctxFactory = pem.certificateOptionsFromFiles(
        str(allFile),
        method=ssl.SSLv2_METHOD,
    )
    assert ssl.SSLv2_METHOD == ctxFactory.method


def test_certificateOptionsFromFilesCatchesMissingKey(tmpdir):
    pytest.importorskip('twisted')
    certFile = tmpdir.join('cert_and_chain.pem')
    certFile.write(''.join(CERT_PEMS))
    with pytest.raises(ValueError):
        pem.certificateOptionsFromFiles(
            str(certFile)
        )


def test_certificateOptionsFromFilesCatchesMultipleKeys(tmpdir):
    pytest.importorskip('twisted')
    allFile = tmpdir.join('key_cert_and_chain.pem')
    allFile.write(KEY_PEM + ''.join(CERT_PEMS) + KEY_PEM2)
    with pytest.raises(ValueError):
        pem.certificateOptionsFromFiles(
            str(allFile)
        )


def test_certificateOptionsFromFilesCatchesMissingCertificate(tmpdir):
    pytest.importorskip('twisted')
    keyFile = tmpdir.join('key.pem')
    keyFile.write(KEY_PEM)
    with pytest.raises(ValueError):
        pem.certificateOptionsFromFiles(
            str(keyFile)
        )


CERT_PEMS = [
    """-----BEGIN CERTIFICATE-----
MIIBfDCCATagAwIBAgIJAK94OSlzVBsWMA0GCSqGSIb3DQEBBQUAMBYxFDASBgNV
BAMTC3BlbS5pbnZhbGlkMB4XDTEzMDcxNzE0NDAyMFoXDTIzMDcxNTE0NDAyMFow
FjEUMBIGA1UEAxMLcGVtLmludmFsaWQwTDANBgkqhkiG9w0BAQEFAAM7ADA4AjEA
vtIM2QADJDHcqxZugx7MULbenrNUFrmoMDfEaedYveWY3wBxOw642L4nFWxN/fwL
AgMBAAGjdzB1MB0GA1UdDgQWBBQ4O0ZSUfTA6C+Y+QZ3MpeMhysxYjBGBgNVHSME
PzA9gBQ4O0ZSUfTA6C+Y+QZ3MpeMhysxYqEapBgwFjEUMBIGA1UEAxMLcGVtLmlu
dmFsaWSCCQCveDkpc1QbFjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAAzEA
XwKIF+Kf4OhcqbdQp253HG2KBt/WZwvNLo/bBlkrGYwfacbGuWT8nKJG70ujdKKf
-----END CERTIFICATE-----
""", """-----BEGIN CERTIFICATE-----
MIIBfDCCATagAwIBAgIJAK9X9aUr9pYtMA0GCSqGSIb3DQEBBQUAMBYxFDASBgNV
BAMTC3BlbS5pbnZhbGlkMB4XDTEzMDcxNzE0NDAyMFoXDTIzMDcxNTE0NDAyMFow
FjEUMBIGA1UEAxMLcGVtLmludmFsaWQwTDANBgkqhkiG9w0BAQEFAAM7ADA4AjEA
v401YT8GeCt6oG076W/n7hxUsFO7sd74/4+2+4OcwMiLEp8BSRdWTk3g/tdF1YHT
AgMBAAGjdzB1MB0GA1UdDgQWBBT/dStoZFKGlnfedA7gtJV1K8JYKDBGBgNVHSME
PzA9gBT/dStoZFKGlnfedA7gtJV1K8JYKKEapBgwFjEUMBIGA1UEAxMLcGVtLmlu
dmFsaWSCCQCvV/WlK/aWLTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAAzEA
uuXLfr1DgOMNt9JGNY5mBjabj3P7ALQYglygEe+QB7d0b/mFngn/aG35TuF5aud9
-----END CERTIFICATE-----
""", """-----BEGIN CERTIFICATE-----
MIIBfDCCATagAwIBAgIJAK4oWdJCuqj2MA0GCSqGSIb3DQEBBQUAMBYxFDASBgNV
BAMTC3BlbS5pbnZhbGlkMB4XDTEzMDcxNzE0NDAyMFoXDTIzMDcxNTE0NDAyMFow
FjEUMBIGA1UEAxMLcGVtLmludmFsaWQwTDANBgkqhkiG9w0BAQEFAAM7ADA4AjEA
wfq/eNemUKJ287E0ydVkzBxX44E6WhmnAN3oq7M881CxXLseNXHe/CRqYGpmziN5
AgMBAAGjdzB1MB0GA1UdDgQWBBQNtv8Fx7AEj4VCmX1I08mk4/viVzBGBgNVHSME
PzA9gBQNtv8Fx7AEj4VCmX1I08mk4/viV6EapBgwFjEUMBIGA1UEAxMLcGVtLmlu
dmFsaWSCCQCuKFnSQrqo9jAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAAzEA
i3qou3qkVXNKuiAFe9dBvz0nhcpAZpXrpwc9R4Qk+rirEqkdCZI1feQKBz4J3ikm
-----END CERTIFICATE-----
"""
]
KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIHyAgEAAjEAvtIM2QADJDHcqxZugx7MULbenrNUFrmoMDfEaedYveWY3wBxOw64
2L4nFWxN/fwLAgMBAAECMCwqsCCV+SQqilnrQj8FJONVwGdZOJBd/iHi6ZXI2zbD
Q9Rv3iOsmqoCb5mqiDra0QIZAPbJRoliNA+2w7/dfttmWcQzcq8xL8qnEwIZAMXx
3hQNtUjuvgohXhZeBkyjP+7G0tceKQIZAPD9sFHsgiZuNU2hgIXDtxkvnGiUQbVF
3QIYMSmKQ6bH8K5DCtcQvDNsExq0pURCV2VJAhgnscmQDJ+DZblOG4zzn4pK7POX
OzCeivo=
-----END RSA PRIVATE KEY-----
"""

KEY_PEM2 = """-----BEGIN RSA PRIVATE KEY-----
MIH0AgEAAjEAv401YT8GeCt6oG076W/n7hxUsFO7sd74/4+2+4OcwMiLEp8BSRdW
Tk3g/tdF1YHTAgMBAAECMCus59Hvi+sUhtZTccitMmXRYeH+hZpt61RidFRLWzwe
nxAWvPxLtU9HC0Pc+zYBWQIZAP8ks93ruPqtoczsmiK+YSoyU+I4bKxM/wIZAMAx
2S5sDr/R+mizU6c8KnSRyQ60jY8HLQIZALZ8b9F4ObPB4IoLaCsVc7WUjX6t0Lxj
zQIZAKm8nHjiF9iSwlsrXMrKWRhgFDf3fzl89QIZALgkMvFA5CmRO+DMECBMsxIb
kjBF/mzooA==
-----END RSA PRIVATE KEY-----
"""

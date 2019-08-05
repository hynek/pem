# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

from itertools import combinations

import certifi

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

import pem

from pem._compat import text_type

from .data import (
    CERT_NO_NEW_LINE,
    CERT_PEMS,
    CERT_PEMS_NO_NEW_LINE,
    CRL_PEMS,
    DH_PEM,
    KEY_PEM_EC_PRIVATE,
    KEY_PEM_PKCS5_ENCRYPTED,
    KEY_PEM_PKCS5_UNENCRYPTED,
    KEY_PEM_PKCS8_ENCRYPTED,
    KEY_PEM_PKCS8_UNENCRYPTED,
    KEY_PEM_PUBLIC,
    KEY_PEM_RSA_PUBLIC,
)


# SHA-1 of "test"
TEST_DIGEST = (
    "PEM string with SHA-1 digest "
    "'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3'"
)


class TestPEMObjects(object):
    def test_cert_has_correct_repr(self):
        """
        Calling repr on a Certificate instance returns the proper string.
        """
        cert = pem.Certificate(b"test")

        assert "<Certificate({0})>".format(TEST_DIGEST) == repr(cert)

    def test_cert_has_correct_str(self):
        """
        Calling str on a Certificate instance returns the proper string.
        """
        cert = pem.Certificate(b"test")

        assert str(cert) == "test"

    def test_cert_req_has_correct_repr(self):
        """
        Calling repr on a CertificateRequest instance returns the proper
        string.
        """
        cert_req = pem.CertificateRequest(b"test")

        assert "<CertificateRequest({0})>".format(TEST_DIGEST) == repr(
            cert_req
        )

    def test_sha1_hexdigest(self):
        """
        obj.sha1_digest contains the correct digest and caches it properly.
        """
        cert = pem.Certificate(b"test")

        assert (
            "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
            == cert.sha1_hexdigest
            == cert.sha1_hexdigest
        )

    def test_as_text(self):
        """
        obj.as_text() returns the contents as Unicode.
        """
        cert_text = pem.Certificate(b"test").as_text()

        assert "test" == cert_text
        assert isinstance(cert_text, text_type)

    def test_cert_req_has_correct_str(self):
        """
        Calling str on a CertificateRequest instance returns the proper string.
        """
        cert_req = pem.CertificateRequest(b"test")

        assert str(cert_req) == "test"

    def test_key_has_correct_repr(self):
        """
        Calling repr on a Key instance returns the proper string.
        """
        key = pem.Key(b"test")

        assert "<Key({0})>".format(TEST_DIGEST) == repr(key)

    def test_key_has_correct_str(self):
        """
        Calling str on a Key instance returns the proper string.
        """
        key = pem.Key(b"test")

        assert str(key) == "test"

    def test_rsa_private_key_has_correct_repr(self):
        """
        Calling repr on a RSAPrivateKey instance returns the proper string.
        """
        key = pem.RSAPrivateKey(b"test")

        assert "<RSAPrivateKey({0})>".format(TEST_DIGEST) == repr(key)

    def test_rsa_public_key_has_correct_repr(self):
        """
        Calling repr on a RSAPublicKey instance returns the proper string.
        """
        key = pem.RSAPublicKey(b"test")

        assert "<RSAPublicKey({0})>".format(TEST_DIGEST) == repr(key)

    def test_rsa_key_has_correct_str(self):
        """
        Calling str on a RSAPrivateKey instance returns the proper string.
        """
        key = pem.RSAPrivateKey(b"test")

        assert str(key) == "test"

    def test_dh_params_has_correct_repr(self):
        """
        Calling repr on a DHParameters instance returns the proper string.
        """
        params = pem.DHParameters(b"test")

        assert "<DHParameters({0})>".format(TEST_DIGEST) == repr(params)

    def test_dh_params_has_correct_str(self):
        """
        Calling str on a DHParameters instance returns the proper string.
        """
        params = pem.DHParameters(b"test")

        assert str(params) == "test"

    def test_crl_has_correct_repr(self):
        """
        Calling repr on a CertificateRevocationList instance returns the proper
        string.
        """
        crl = pem.CertificateRevocationList(b"test")

        assert "<CertificateRevocationList({0})>".format(TEST_DIGEST) == repr(
            crl
        )

    def test_crl_has_correct_str(self):
        """
        Calling str on a CertificateRevocationList instance returns the proper
        string.
        """
        crl = pem.CertificateRevocationList(b"test")

        assert str(crl) == "test"

    def test_certificate_unicode(self):
        """
        Passing unicode to Certificate encodes the string as ASCII.
        """
        cert = pem.Certificate(u"a string")

        assert cert.as_bytes() == b"a string"
        assert str(cert) == "a string"

    def test_certificate_request_unicode(self):
        """
        Passing unicode to CertificateRequest encodes the string as ASCII.
        """
        cert_req = pem.CertificateRequest(u"a string")

        assert cert_req.as_bytes() == b"a string"
        assert str(cert_req) == "a string"

    def test_key_unicode(self):
        """
        Passing unicode to Key encodes the string as ASCII.
        """
        key = pem.Key(u"a string")

        assert key.as_bytes() == b"a string"
        assert str(key) == "a string"

    def test_rsa_key_unicode(self):
        """
        Passing unicode to RSAPrivateKey encodes the string as ASCII.
        """
        key = pem.RSAPrivateKey(u"a string")

        assert key.as_bytes() == b"a string"
        assert str(key) == "a string"

    def test_dhparams_unicode_deprecated(self):
        """
        Passing unicode to DHParameters encodes the string as ASCII.
        """
        params = pem.DHParameters(u"a string")

        assert params.as_bytes() == b"a string"
        assert str(params) == "a string"

    def test_crl_unicode(self):
        """
        Passing unicode to CertificateRevocationList encodes the string as
        ASCII.
        """
        crl = pem.CertificateRevocationList(u"a string")

        assert crl.as_bytes() == b"a string"
        assert str(crl) == "a string"

    def test_certs_equal(self):
        """
        Two Certificate instances with equal contents are equal.
        """
        cert1 = pem.Certificate(b"test")
        cert2 = pem.Certificate(b"test")

        assert cert1 == cert2
        assert cert2 == cert1
        assert hash(cert1) == hash(cert2)

    def test_cert_reqs_equal(self):
        """
        Two Certificate Request instances with equal contents are equal.
        """
        cert_req1 = pem.CertificateRequest(b"test")
        cert_req2 = pem.CertificateRequest(b"test")

        assert cert_req1 == cert_req2
        assert cert_req2 == cert_req1
        assert hash(cert_req1) == hash(cert_req2)

    def test_keys_equal(self):
        """
        Two Key instances with equal contents are equal and have equal hashes.
        """
        key1 = pem.Key(b"test")
        key2 = pem.Key(b"test")

        assert key1 == key2
        assert key2 == key1
        assert hash(key1) == hash(key2)

    def test_rsa_keys_equal(self):
        """
        Two RSAPrivateKey instances with equal contents are equal and have
        equal hashes.
        """

        key1 = pem.RSAPrivateKey(b"test")
        key2 = pem.RSAPrivateKey(b"test")

        assert key1 == key2
        assert key2 == key1
        assert hash(key1) == hash(key2)

    def test_dh_params_equal(self):
        """
        Two DHParameters instances with equal contents are equal and have equal
        hashes.
        """
        params1 = pem.DHParameters(b"test")
        params2 = pem.DHParameters(b"test")

        assert params1 == params2
        assert params2 == params1
        assert hash(params1) == hash(params2)

    def test_crl_equal(self):
        """
        Two CertificateRevocationList instances with equal contents are equal
        and have equal hashes.
        """
        crl1 = pem.CertificateRevocationList(b"test")
        crl2 = pem.CertificateRevocationList(b"test")

        assert crl1 == crl2
        assert crl2 == crl1
        assert hash(crl1) == hash(crl2)

    def test_cert_contents_unequal(self):
        """
        Two Certificate instances with unequal contents are not equal.
        """
        cert1 = pem.Certificate(b"test1")
        cert2 = pem.Certificate(b"test2")

        assert cert1 != cert2
        assert cert2 != cert1

    def test_cert_req_contents_unequal(self):
        """
        Two CertificateRequest instances with unequal contents are not equal.
        """
        cert_req1 = pem.CertificateRequest(b"test1")
        cert_req2 = pem.CertificateRequest(b"test2")

        assert cert_req1 != cert_req2
        assert cert_req2 != cert_req1

    def test_crl_unequal(self):
        """
        Two CertificateRevocationList instances with unequal contents are not
        equal.
        """
        crl1 = pem.CertificateRevocationList(b"test1")
        crl2 = pem.CertificateRevocationList(b"test2")

        assert crl1 != crl2
        assert crl2 != crl1

    def test_different_objects_unequal(self):
        """
        Two PEM objects of different types but with equal contents are not
        equal.
        """
        c = b"test"

        pems = [
            pem.Certificate(c),
            pem.CertificateRequest(c),
            pem.Key(c),
            pem.RSAPrivateKey(c),
            pem.CertificateRevocationList(c),
        ]

        for pem1, pem2 in combinations(pems, 2):
            assert not pem1 == pem2
            assert pem1 != pem2

    def test_incompatible_types(self):
        """
        A PEM object is not equal to some other arbitrary object.
        """
        cert = pem.Certificate(b"test")

        assert not cert == object()
        assert cert != object()
        assert object() != cert


def load_rsa_key(key, password=None):
    return serialization.load_pem_private_key(
        key.as_bytes(), password=password, backend=default_backend()
    )


class TestParse(object):
    """
    Tests for parsing input with one or multiple PEM objects.
    """

    def test_key_pkcs5_unencrypted(self):
        """
        It can load an unencrypted PKCS#5 RSA key as PEM string
        as an RSAPrivateKey.
        """
        rv = pem.parse(KEY_PEM_PKCS5_UNENCRYPTED)
        key, = rv

        assert isinstance(key, pem.RSAPrivateKey)
        assert KEY_PEM_PKCS5_UNENCRYPTED == key.as_bytes()

        crypto_key = load_rsa_key(key)

        assert isinstance(crypto_key, RSAPrivateKey)
        assert 512, crypto_key.key_size()

    def test_key_pkcs5_encrypted(self):
        """
        It can load an encrypted PKCS#5 RSA key as PEM string
        as an RSAPrivateKey.
        """

        rv = pem.parse(KEY_PEM_PKCS5_ENCRYPTED)
        key, = rv

        assert isinstance(key, pem.RSAPrivateKey)
        assert KEY_PEM_PKCS5_ENCRYPTED == key.as_bytes()

        crypto_key = load_rsa_key(key, password=b"test")

        assert isinstance(crypto_key, RSAPrivateKey)
        assert 512, crypto_key.key_size()

    def test_key_pkcs8_unencrypted(self):
        """
        It can load an unencrypted PKCS#8 RSA key as PEM string
        as an Key.
        """
        rv = pem.parse(KEY_PEM_PKCS8_UNENCRYPTED)
        key, = rv

        assert isinstance(key, pem.Key)
        assert KEY_PEM_PKCS8_UNENCRYPTED == key.as_bytes()

        crypto_key = load_rsa_key(key)

        assert isinstance(crypto_key, RSAPrivateKey)
        assert 512, crypto_key.key_size()

    def test_key_pkcs8_encrypted(self):
        """
        It can load an encrypted PKCS#8 RSA key as PEM string
        as an Key.
        """
        rv = pem.parse(KEY_PEM_PKCS8_ENCRYPTED)
        key, = rv

        assert isinstance(key, pem.Key)
        assert KEY_PEM_PKCS8_ENCRYPTED == key.as_bytes()

        crypto_key = load_rsa_key(key, password=b"test")

        assert isinstance(crypto_key, RSAPrivateKey)
        assert 512, crypto_key.key_size()

    def test_certificates(self):
        """
        Parses a PEM string with multiple certificates into a list of
        corresponding Certificates.
        """
        certs = pem.parse(b"".join(CERT_PEMS))

        assert all(isinstance(c, pem.Certificate) for c in certs)
        assert CERT_PEMS == [cert.as_bytes() for cert in certs]

    def test_certificate_no_new_line(self):
        """
        Parses a PEM string without a new line at the end
        """
        cert, = pem.parse(CERT_NO_NEW_LINE)

        assert isinstance(cert, pem.Certificate)
        assert CERT_NO_NEW_LINE == cert.as_bytes()

    def test_certificates_no_new_line(self):
        """
        Parses a PEM string with multiple certificates without a new line
        at the end into a list of corresponding Certificates.
        """
        certs = pem.parse(b"".join(CERT_PEMS_NO_NEW_LINE))

        assert all(isinstance(c, pem.Certificate) for c in certs)
        assert CERT_PEMS_NO_NEW_LINE == [cert.as_bytes() for cert in certs]

    def test_dh(self):
        """
        Parses a PEM string with with DH parameters into a DHParameters.
        """
        rv = pem.parse(DH_PEM)
        dh, = rv

        assert isinstance(dh, pem.DHParameters)
        assert DH_PEM == dh.as_bytes()

    def test_crl(self):
        """
        Parses a PEM string with multiple certificate revocation lists into a
        list of corresponding CertificateRevocationLists
        """
        crls = pem.parse(b"".join(CRL_PEMS))

        assert all(isinstance(c, pem.CertificateRevocationList) for c in crls)
        assert CRL_PEMS == [crl.as_bytes() for crl in crls]

    def test_file(self, tmpdir):
        """
        A file with multiple certificate PEMs is parsed into a list of
        corresponding Certificates.
        """
        certs_file = tmpdir.join("certs.pem")
        certs_file.write(b"".join(CERT_PEMS))
        certs = pem.parse_file(str(certs_file))

        assert all(isinstance(c, pem.Certificate) for c in certs)
        assert CERT_PEMS == [cert.as_bytes() for cert in certs]

    def test_loads_certifi(self):
        """
        Loading certifi returns a list of Certificates.
        """
        cas = pem.parse_file(certifi.where())

        assert isinstance(cas, list)
        assert all(isinstance(ca, pem.Certificate) for ca in cas)

    def test_allows_lf(self):
        """
        \n and \r\n are treated equal.
        """
        lf_pem = KEY_PEM_PKCS5_UNENCRYPTED.replace(b"\n", b"\r\n")
        rv, = pem.parse(lf_pem)

        assert rv.as_bytes() == lf_pem

    def test_rsa_public_key(self):
        """
        Detects and loads RSA public keys.
        """
        key = pem.parse(KEY_PEM_RSA_PUBLIC)[0]

        assert isinstance(key, pem.PublicKey)
        assert isinstance(key, pem.RSAPublicKey)

    def test_generic_public_key(self):
        """
        Detects and loads generic public keys.
        """
        key = pem.parse(KEY_PEM_PUBLIC)[0]

        assert isinstance(key, pem.PublicKey)

    def test_ec_private_key(self):
        """
        Detects and loads EC private keys.
        """
        key = pem.parse(KEY_PEM_EC_PRIVATE)[0]

        assert isinstance(key, pem.ECPrivateKey)

# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

import certifi

import pem

from pem._compat import text_type

from .data import (
    CERT_NO_NEW_LINE,
    CERT_PEMS,
    CERT_PEMS_NO_NEW_LINE,
    DH_PEM,
    KEY_PEM,
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

    def test_rsa_key_has_correct_repr(self):
        """
        Calling repr on a RSAPrivateKey instance returns the proper string.
        """
        key = pem.RSAPrivateKey(b"test")

        assert "<RSAPrivateKey({0})>".format(TEST_DIGEST) == repr(key)

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

    def test_different_objects_unequal(self):
        """
        Two PEM objects of different types but with equal contents are not
        equal.
        """
        cert = pem.Certificate(b"test")
        cert_req = pem.CertificateRequest(b"test")
        key = pem.Key(b"test")
        rsa_key = pem.RSAPrivateKey(b"test")

        assert not cert == key
        assert cert != key
        assert key != cert
        assert cert != cert_req
        assert cert_req != cert
        assert key != rsa_key
        assert rsa_key != key

    def test_incompatible_types(self):
        """
        A PEM object is not equal to some other arbitrary object.
        """
        cert = pem.Certificate(b"test")

        assert not cert == object()
        assert cert != object()
        assert object() != cert


class TestParse(object):
    def test_key(self):
        """
        Parses a PEM string with a key into an RSAPrivateKey.
        """
        rv = pem.parse(KEY_PEM)
        key, = rv

        assert isinstance(key, pem.RSAPrivateKey)
        assert KEY_PEM == key.as_bytes()

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
        lf_pem = KEY_PEM.replace(b"\n", b"\r\n")
        rv, = pem.parse(lf_pem)

        assert rv.as_bytes() == lf_pem

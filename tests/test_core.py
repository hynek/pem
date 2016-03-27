# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

import certifi
import pytest

import pem

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
        cert = pem.Certificate(u'a string')
        assert cert.as_bytes() == b'a string'
        assert str(cert) == 'a string'

    def test_key_unicode(self):
        """
        Passing unicode to Key encodes the string as ASCII.
        """
        key = pem.Key(u'a string')
        assert key.as_bytes() == b'a string'
        assert str(key) == 'a string'

    def test_rsa_key_unicode(self):
        """
        Passing unicode to RSAPrivateKey encodes the string as ASCII.
        """
        key = pem.RSAPrivateKey(u'a string')
        assert key.as_bytes() == b'a string'
        assert str(key) == 'a string'

    def test_dhparams_unicode_deprecated(self):
        """
        Passing unicode to DHParameters encodes the string as ASCII.
        """
        params = pem.DHParameters(u'a string')
        assert params.as_bytes() == b'a string'
        assert str(params) == 'a string'


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
        certs = pem.parse(b''.join(CERT_PEMS))
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
        certs = pem.parse(b''.join(CERT_PEMS_NO_NEW_LINE))
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
        certs_file = tmpdir.join('certs.pem')
        certs_file.write(b''.join(CERT_PEMS))
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

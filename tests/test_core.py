# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)

import certifi

import pem

from .data import (
    CERT_NO_NEW_LINE,
    CERT_PEMS,
    CERT_PEMS_NO_NEW_LINE,
    DH_PEM,
    KEY_PEM,
)


class TestPEMObjects(object):
    def test_cert_has_correct_repr(self):
        """
        Calling repr on a Certificate instance returns the proper string.
        """
        cert = pem.Certificate('test')
        assert "<Certificate(pem_str='test')>" == repr(cert)

    def test_rsa_key_has_correct_repr(self):
        """
        Calling repr on a RSAPrivateKey instance returns the proper string.
        """
        key = pem.RSAPrivateKey('test')
        assert "<RSAPrivateKey(pem_str='test')>" == repr(key)

    def test_dh_params_has_correct_repr(self):
        """
        Calling repr on a DHParameters instance returns the proper string.
        """
        key = pem.DHParameters('test')
        assert "<DHParameters(pem_str='test')>" == repr(key)


class TestParse(object):
    def test_key(self):
        """
        Parses a PEM string with a key into an RSAPrivateKey.
        """
        rv = pem.parse(KEY_PEM)
        key, = rv
        assert isinstance(key, pem.RSAPrivateKey)
        assert KEY_PEM == str(key)

    def test_certificates(self):
        """
        Parses a PEM string with multiple certificates into a list of
        corresponding Certificates.
        """
        certs = pem.parse(''.join(CERT_PEMS))
        assert all(isinstance(c, pem.Certificate) for c in certs)
        assert CERT_PEMS == [str(cert) for cert in certs]

    def test_certificate_no_new_line(self):
        """
        Parses a PEM string without a new line at the end
        """
        cert, = pem.parse(CERT_NO_NEW_LINE)
        assert isinstance(cert, pem.Certificate)
        assert CERT_NO_NEW_LINE == str(cert)

    def test_certificates_no_new_line(self):
        """
        Parses a PEM string with multiple certificates without a new line
        at the end into a list of corresponding Certificates.
        """
        certs = pem.parse(''.join(CERT_PEMS_NO_NEW_LINE))
        assert all(isinstance(c, pem.Certificate) for c in certs)
        assert CERT_PEMS_NO_NEW_LINE == [str(cert) for cert in certs]

    def test_dh(self):
        """
        Parses a PEM string with with DH parameters into a DHParameters.
        """
        rv = pem.parse(DH_PEM)
        dh, = rv
        assert isinstance(dh, pem.DHParameters)
        assert DH_PEM == str(dh)

    def test_file(self, tmpdir):
        """
        A file with multiple certificate PEMs is parsed into a list of
        corresponding Certificates.
        """
        certs_file = tmpdir.join('certs.pem')
        certs_file.write(''.join(CERT_PEMS))
        certs = pem.parse_file(str(certs_file))
        assert all(isinstance(c, pem.Certificate) for c in certs)
        assert CERT_PEMS == [str(cert) for cert in certs]

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
        lf_pem = KEY_PEM.replace("\n", "\r\n")
        rv, = pem.parse(lf_pem)
        assert str(rv) == lf_pem

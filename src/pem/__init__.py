# SPDX-FileCopyrightText: 2013 Hynek Schlawack <hs@ox.cx>
#
# SPDX-License-Identifier: MIT

from ._core import (
    AbstractPEMObject,
    Certificate,
    CertificateRequest,
    CertificateRevocationList,
    DHParameters,
    DSAPrivateKey,
    ECPrivateKey,
    Key,
    OpenPGPPrivateKey,
    OpenPGPPublicKey,
    OpenSSHPrivateKey,
    OpenSSLTrustedCertificate,
    PrivateKey,
    PublicKey,
    RSAPrivateKey,
    RSAPublicKey,
    SSHCOMPrivateKey,
    SSHPublicKey,
    parse,
    parse_file,
)


try:
    from . import twisted
except ImportError:
    twisted = None  # type: ignore[assignment]


__version__ = "22.1.0.dev0"
__author__ = "Hynek Schlawack"
__license__ = "MIT"
__description__ = "PEM file parsing in Python."
__url__ = "https://pem.readthedocs.io/"
__uri__ = __url__
__email__ = "hs@ox.cx"


__all__ = [
    "AbstractPEMObject",
    "Certificate",
    "CertificateRequest",
    "CertificateRevocationList",
    "DHParameters",
    "DSAPrivateKey",
    "ECPrivateKey",
    "Key",
    "OpenPGPPrivateKey",
    "OpenPGPPublicKey",
    "OpenSSHPrivateKey",
    "OpenSSLTrustedCertificate",
    "parse_file",
    "parse",
    "PrivateKey",
    "PublicKey",
    "RSAPrivateKey",
    "RSAPublicKey",
    "SSHCOMPrivateKey",
    "SSHPublicKey",
    "twisted",
]

from __future__ import absolute_import, division, print_function

from ._core import (
    Certificate,
    CertificateRequest,
    DHParameters,
    Key,
    RSAPrivateKey,
    parse,
    parse_file,
)


try:
    from . import twisted
except ImportError:
    twisted = None


__version__ = "18.1.0.dev0"
__author__ = "Hynek Schlawack"
__license__ = "MIT"
__description__ = "Easy PEM file parsing in Python."
__uri__ = "https://pem.readthedocs.io/"
__email__ = "hs@ox.cx"


_DEPRECATION_WARNING = (
    "Calling {func} from the pem package is deprecated as of pem 15.0.0.  "
    "Please use pem.twisted.{func} instead."
)


def certificateOptionsFromFiles(*args, **kw):
    """
    Deprecated function.  Please use pem.twisted.certificateOptionsFromFiles.
    """
    import warnings

    from .twisted import certificateOptionsFromFiles

    warnings.warn(
        _DEPRECATION_WARNING.format(func="certificateOptionsFromFiles"),
        DeprecationWarning,
    )
    return certificateOptionsFromFiles(*args, **kw)


def certificateOptionsFromPEMs(*args, **kw):
    """
    Deprecated function.  Please use pem.twisted.certificateOptionsFromPEMs.
    """
    import warnings

    from .twisted import certificateOptionsFromPEMs

    warnings.warn(
        _DEPRECATION_WARNING.format(func="certificateOptionsFromPEMs"),
        DeprecationWarning,
    )
    return certificateOptionsFromPEMs(*args, **kw)


__all__ = [
    "Certificate",
    "CertificateRequest",
    "DHParameters",
    "Key",
    "RSAPrivateKey",
    "certificateOptionsFromFiles",
    "certificateOptionsFromPEMs",
    "parse",
    "parse_file",
    "twisted",
]

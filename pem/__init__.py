from __future__ import absolute_import, division, print_function

from . import twisted
from ._core import (
    Certificate,
    DHParameters,
    Key,
    RSAPrivateKey,
    parse,
    parse_file,
)
from .twisted import (
    certificateOptionsFromFiles as certificateOptionsFromFilesOriginal,
    certificateOptionsFromPEMs as certificateOptionsFromPEMsOriginal,
)


__version__ = "15.0.0"
__author__ = "Hynek Schlawack"
__license__ = "MIT"
__description__ = "Easy PEM file parsing in Python."
__uri__ = "https://pem.readthedocs.org/"
__email__ = "hs@ox.cx"


_DEPRECATION_WARNING = (
    "Calling {func} from the pem package is deprecated as of pem 15.0.0.  "
    "Please use pem.twisted.{func} instead."
)


def certificateOptionsFromFiles(*a, **kw):
    """
    Deprecated function.  Please use pem.twisted.certificateOptionsFromFiles.
    """
    import warnings
    warnings.warn(
        _DEPRECATION_WARNING.format(func="certificateOptionsFromFiles"),
        DeprecationWarning
    )
    return certificateOptionsFromFilesOriginal(*a, **kw)


def certificateOptionsFromPEMs(*a, **kw):
    """
    Deprecated function.  Please use pem.twisted.certificateOptionsFromPEMs.
    """
    import warnings
    warnings.warn(
        _DEPRECATION_WARNING.format(func="certificateOptionsFromPEMs"),
        DeprecationWarning
    )
    return certificateOptionsFromPEMsOriginal(*a, **kw)


__all__ = [
    "Certificate",
    "DHParameters",
    "Key",
    "RSAPrivateKey",
    "certificateOptionsFromFiles",
    "certificateOptionsFromPEMs",
    "parse",
    "parse_file",
    "twisted",
]

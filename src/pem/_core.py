# SPDX-FileCopyrightText: 2013 Hynek Schlawack <hs@ox.cx>
#
# SPDX-License-Identifier: MIT

"""
Framework agnostic PEM file parsing functions.
"""

from __future__ import annotations

import re

from pathlib import Path

from ._object_types import _PEM_TO_CLASS, AbstractPEMObject


# See https://tools.ietf.org/html/rfc1421
# and https://datatracker.ietf.org/doc/html/rfc4716 for space instead of fifth dash.
_PEM_RE = re.compile(
    b"----[- ]BEGIN ("
    + b"|".join(_PEM_TO_CLASS)
    + b""")[- ]----\r?
(?P<payload>.+?)\r?
----[- ]END \\1[- ]----\r?\n?""",
    re.DOTALL,
)


def parse(pem_str: bytes | str) -> list[AbstractPEMObject]:
    """
    Extract PEM-like objects from *pem_str*.

    Returns:
        list[AbstractPEMObject]: list of :ref:`pem-objects`

    .. versionchanged:: 23.1.0
       *pem_str* can now also be a... :class:`str`.
    """
    return [
        _PEM_TO_CLASS[match.group(1)](match.group(0))
        for match in _PEM_RE.finditer(
            pem_str if isinstance(pem_str, bytes) else pem_str.encode()
        )
    ]


def parse_file(file_name: str | Path) -> list[AbstractPEMObject]:
    """
    Read *file_name* and parse PEM objects from it using :func:`parse`.

    Returns:
        list[AbstractPEMObject]: list of :ref:`pem-objects`

    .. versionchanged:: 23.1.0
       *file_name* can now also be a :class:`~pathlib.Path`.
    """
    return parse(Path(file_name).read_bytes())

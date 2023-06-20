# SPDX-FileCopyrightText: 2013 Hynek Schlawack <hs@ox.cx>
#
# SPDX-License-Identifier: MIT

"""
This file is used to test the type annotations of the public API. It is NOT
meant to be executed.
"""

from __future__ import annotations

import pem


objs: list[pem.AbstractPEMObject]

objs = pem.parse_file("foo.pem")
objs = pem.parse("PEM")
objs = pem.parse(b"PEM")

if objs:
    s: str = objs[0].as_text()
    b: bytes = objs[0].as_bytes()
    s = objs[0].sha1_hexdigest

    b = objs[0].bytes_payload
    b = objs[0].decoded_payload
    s = objs[0].text_payload

    d: dict[str, str] = objs[0].meta_headers

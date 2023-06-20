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

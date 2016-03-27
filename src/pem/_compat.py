from __future__ import absolute_import, division, print_function


import sys


PY3 = sys.version_info[0] == 3


if PY3:
    unicode = str
else:
    unicode = unicode

from __future__ import absolute_import, division, print_function

import sys


PY2 = sys.version_info[0] == 2


if PY2:
    text_type = unicode  # noqa
else:
    text_type = str


def with_metaclass(meta, *bases):
    """
    Create a base class with a metaclass.

    Based on work by Benjamin Peterson.
    """

    class metaclass(meta):
        def __new__(cls, name, this_bases, d):
            return meta(name, bases, d)

    return type.__new__(metaclass, "temporary_class", (), {})

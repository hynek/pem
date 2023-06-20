# SPDX-FileCopyrightText: 2013 Hynek Schlawack <hs@ox.cx>
#
# SPDX-License-Identifier: MIT

from importlib import metadata

import pytest

import pem


class TestLegacyMetadataHack:
    def test_version(self, recwarn):
        """
        pem.__version__ returns the correct version and doesn't warn.
        """
        assert metadata.version("pem") == pem.__version__
        assert [] == recwarn.list

    def test_description(self):
        """
        pem.__description__ returns the correct description.
        """
        with pytest.deprecated_call():
            assert "PEM file parsing in Python." == pem.__description__

    def test_uri(self):
        """
        pem.__uri__ returns the correct project URL.
        """
        with pytest.deprecated_call():
            assert "https://pem.readthedocs.io/" == pem.__uri__

    def test_email(self):
        """
        pem.__email__ returns Hynek's email address.
        """
        with pytest.deprecated_call():
            assert "hs@ox.cx" == pem.__email__

    def test_does_not_exist(self):
        """
        Asking for unsupported dunders raises an AttributeError.
        """
        with pytest.raises(
            AttributeError,
            match="module pem has no attribute __yolo__",
        ):
            pem.__yolo__  # noqa: B018

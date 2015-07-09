pem: Easy PEM file parsing
==========================

.. image:: https://img.shields.io/pypi/v/pem.svg
   :target: https://pypi.python.org/pypi/pem/
   :alt: Latest Version

.. image:: https://secure.travis-ci.org/hynek/pem.png
   :target: https://secure.travis-ci.org/hynek/pem
   :alt: CI status

.. image:: https://codecov.io/github/hynek/pem/coverage.svg?branch=master
   :target: https://codecov.io/github/hynek/pem?branch=master
   :alt: Coverage

.. teaser-begin

``pem`` is an MIT_-licensed Python module for parsing and splitting of `PEM files`_, i.e. Base64 encoded DER keys and certificates.

It runs on Python 2.6, 2.7, 3.3, 3.4, and PyPy 2.0+, has no dependencies and does not attempt to interpret the certificate data in any way.
``pem`` is intended to ease the handling of PEM files in combination with PyOpenSSL_ and – by extension – Twisted_.

It’s born from my personal need because of the inconsistent handling of chain certificates by various servers: some servers (like Apache_) expect them to be a separate file while others (like nginx_) expect them concatenated to the server certificate.
Since I want my Python software to be universal and to be able to cope with both, ``pem`` was born.

``pem``\ ’s documentation lives at `Read the Docs <https://pem.readthedocs.org/>`_, the code on `GitHub <https://github.com/hynek/pem>`_.


Future
------

``pem`` currently only supports the PyOpenSSL/Twisted combo because that’s what I’m using.
I’d be more than happy to merge support for additional frameworks though!


.. _MIT: https://choosealicense.com/licenses/mit/
.. _`PEM files`: https://en.wikipedia.org/wiki/X.509#Certificate_filename_extensions
.. _Apache: https://httpd.apache.org
.. _nginx: http://nginx.org/en/
.. _PyOpenSSL: http://www.pyopenssl.org/
.. _Twisted: https://twistedmatrix.com/documents/current/api/twisted.internet.ssl.Certificate.html#loadPEM

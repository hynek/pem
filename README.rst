pem: Easy PEM file parsing
==========================

.. image:: https://img.shields.io/pypi/v/pem.svg
   :target: https://pypi.org/project/pem/
   :alt: PyPI

.. image:: https://readthedocs.org/projects/pem/badge/?version=stable
   :target: https://pem.readthedocs.io/en/stable/?badge=stable
   :alt: Documentation Status

.. image:: https://dev.azure.com/the-hynek/pem/_apis/build/status/hynek.pem?branchName=master
   :target: https://dev.azure.com/the-hynek/pem/_build?definitionId=1
   :alt: CI Status

.. image:: https://codecov.io/gh/hynek/pem/branch/master/graph/badge.svg
   :target: https://codecov.io/github/hynek/pem
   :alt: Coverage

.. image:: https://www.irccloud.com/invite-svg?channel=%23cryptography-dev&amp;hostname=irc.freenode.net&amp;port=6697&amp;ssl=1
   :target: https://www.irccloud.com/invite?channel=%23cryptography-dev&amp;hostname=irc.freenode.net&amp;port=6697&amp;ssl=1

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
   :target: https://github.com/psf/black
   :alt: Code style: black

.. image:: http://www.mypy-lang.org/static/mypy_badge.svg
   :target: http://mypy-lang.org
   :alt: Checked with mypy

.. teaser-begin

``pem`` is an MIT_-licensed Python module for parsing and splitting of `PEM files`_, i.e. Base64 encoded DER keys and certificates.

It runs on Python 2.7, 3.4+, and PyPy, has no dependencies, and does not attempt to interpret the certificate data in any way.

It’s born from the need to load keys, certificates, trust chains, and DH parameters from various certificate deployments: some servers (like Apache_) expect them to be a separate file, others (like nginx_) expect them concatenated to the server certificate and finally some (like HAProxy_) expect key, certificate, and chain to be in one file.
With ``pem``, your Python application can cope with all of those scenarios:

.. code-block:: pycon

   >>> import pem
   >>> certs = pem.parse_file("chain.pem")
   >>> certs
   [<Certificate(PEM string with SHA-1 digest '...')>, <Certificate(PEM string with SHA-1 digest '...')>]
   >>> str(certs[0])
   '-----BEGIN CERTIFICATE-----\n...'

Additionally to the vanilla parsing code, ``pem`` also contains helpers for Twisted_ that save a lot of boilerplate code.

``pem``\ ’s documentation lives at `Read the Docs <https://pem.readthedocs.io/>`_, the code on `GitHub <https://github.com/hynek/pem>`_.


.. _MIT: https://choosealicense.com/licenses/mit/
.. _`PEM files`: https://en.wikipedia.org/wiki/X.509#Certificate_filename_extensions
.. _Apache: https://httpd.apache.org/
.. _nginx: https://nginx.org/
.. _HAProxy: https://www.haproxy.org/
.. _Twisted: https://twistedmatrix.com/documents/current/api/twisted.internet.ssl.Certificate.html#loadPEM

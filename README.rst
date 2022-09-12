pem: PEM file parsing for Python
================================

.. image:: https://img.shields.io/badge/Docs-Read%20The%20Docs-black
   :target: https://pem.readthedocs.io/en/stable/
   :alt: Documentation

.. image:: https://img.shields.io/badge/license-MIT-C06524
   :target: https://github.com/hynek/pem/blob/main/LICENSE
   :alt: License: MIT

.. image:: https://img.shields.io/pypi/v/pem
   :target: https://pypi.org/project/pem/
   :alt: PyPI version

.. image:: https://static.pepy.tech/personalized-badge/pem?period=month&units=international_system&left_color=grey&right_color=blue&left_text=Downloads%20/%20Month
   :target: https://pepy.tech/project/pem
   :alt: Downloads / Month

.. teaser-begin

*pem* is an MIT_-licensed Python module for parsing and splitting of `PEM files`_, i.e. Base64-encoded DER keys and certificates.

It runs on Python 3.7+, has no dependencies, and does not attempt to interpret the certificate data in any way.

It’s born from the need to load keys, certificates, trust chains, and DH parameters from various certificate deployments: some servers (like Apache_) expect them to be a separate file, others (like nginx_) expect them concatenated to the server certificate and finally some (like HAProxy_) expect key, certificate, and chain to be in one file.
With *pem*, your Python application can cope with all of those scenarios:

.. code-block:: pycon

   >>> import pem
   >>> certs = pem.parse_file("chain.pem")
   >>> certs
   [<Certificate(PEM string with SHA-1 digest '...')>, <Certificate(PEM string with SHA-1 digest '...')>]
   >>> str(certs[0])
   '-----BEGIN CERTIFICATE-----\n...'

Additionally to the vanilla parsing code, *pem* also contains helpers for Twisted_ that save a lot of boilerplate code.

*pem* is available from `PyPI <https://pypi.org/project/pem/>`_, its documentation lives at `Read the Docs <https://pem.readthedocs.io/>`_, the code on `GitHub <https://github.com/hynek/pem>`_.


*pem* for Enterprise
--------------------

Available as part of the Tidelift Subscription.

The maintainers of *pem* and thousands of other packages are working with Tidelift to deliver commercial support and maintenance for the open source packages you use to build your applications.
Save time, reduce risk, and improve code health, while paying the maintainers of the exact packages you use.
`Learn more. <https://tidelift.com/subscription/pkg/pypi-pem?utm_source=pypi-pem&utm_medium=referral&utm_campaign=enterprise>`_

.. _MIT: https://choosealicense.com/licenses/mit/
.. _`PEM files`: https://en.wikipedia.org/wiki/X.509#Certificate_filename_extensions
.. _Apache: https://httpd.apache.org/
.. _nginx: https://nginx.org/
.. _HAProxy: https://www.haproxy.org/
.. _Twisted: https://twistedmatrix.com/documents/current/api/twisted.internet.ssl.Certificate.html#loadPEM

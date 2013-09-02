pem: Easy PEM file parsing
==========================

.. image:: https://secure.travis-ci.org/hynek/pem.png
        :target: https://secure.travis-ci.org/hynek/pem

*pem* is an MIT_-licensed Python module for parsing and splitting of `PEM files`_, i.e. Base64 encoded DER keys and certificates.

It runs on Python 2.6, 2.7, 3.3, and PyPy 2.0+, has no dependencies and does not attempt to interpret the certificate data in any way.
*pem* is intended to ease the handling of PEM files in combination with PyOpenSSL_ and – by extension – Twisted_.

It’s born from my personal need because of the inconsistent handling of chain certificates by various servers: some servers (like Apache_) expect them to be a separate file while others (like nginx_) expect them concatenated to the server certificate.
Since I want my Python software to be universal and to be able to cope with both, *pem* was born.

The core API call is the function ``parse()``:

.. code-block:: python

   import pem

   with open('cert.pem', 'rb') as f:
      certs = pem.parse(f.read())

The function returns a list of valid PEM objects found in the string supplied.
Currently possible types are ``Certificate`` and ``RSAPrivateKey``.
Both can be transformed using ``str()`` into plain strings for other APIs.
They don’t offer any other public API at the moment.

Convenience
-----------

Since *pem* is mostly a convenience module, there are several helper functions.

Files
+++++

``parse_file(file_name)`` reads the file ``file_name`` and parses its contents.
So the following example is equivalent with the first one:

.. code-block:: python

   import pem

   certs = pem.parse_file('cert.pem')


Twisted
+++++++

A typical use case in Twisted with the APIs above would be:

.. code-block:: python

   import pem

   from twisted.internet import ssl

   key = pem.parse_file('key.pem')
   cert, chain = pem.parse_file('cert_and_chain.pem')
   cert = ssl.PrivateCertificate.loadPEM(str(key) + str(cert))
   chainCert = ssl.Certificate.loadPEM(str(chain))

   ctxFactory = ssl.CertificateOptions(
         privateKey=cert.privateKey.original,
         certificate=cert.original,
         extraCertChain=[chainCert.original],
   )

Turns out, this is the major use case for me.
Therefore it can be simplified to:


.. code-block:: python

   import pem

   ctxFactory = pem.certificateOptionsFromFiles(
      'key.pem', 'cert_and_chain.pem',
   )


The first certificate found will be used as the server certificate, the rest is passed as the chain.
You can pass as many PEM files as you like.
Therefore you can distribute your key, certificate, and chain certificates over a arbitrary number of files.
A ``ValueError`` is raised if more than one key, no key, or no certificate are found.
Any further keyword arguments will be passed to CertificateOptions_.


Future
------

*pem* currently only supports the PyOpenSSL/Twisted combo because that’s what I’m using.
I’d be more than happy to merge support for additional frameworks though!


.. _MIT: http://choosealicense.com/licenses/mit/
.. _`PEM files`: http://en.wikipedia.org/wiki/X.509#Certificate_filename_extensions
.. _Apache: http://httpd.apache.org
.. _nginx: http://nginx.org/en/
.. _PyOpenSSL: https://launchpad.net/pyopenssl
.. _Twisted: http://twistedmatrix.com/documents/current/api/twisted.internet.ssl.Certificate.html#loadPEM
.. _CertificateOptions: http://twistedmatrix.com/documents/current/api/twisted.internet.ssl.CertificateOptions.html


.. image:: https://d2weczhvl823v0.cloudfront.net/hynek/pem/trend.png
   :alt: Bitdeli badge
   :target: https://bitdeli.com/free


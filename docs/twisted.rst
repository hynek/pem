Twisted
=======

A typical use case in Twisted with the APIs above would be::

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

If you want to load your PEM data from somewhere else, you can also use
``certificateOptionsFromPEMs`` to do the same thing with already-loaded
``Certificate``, ``Key``, and ``RSAPrivateKey`` objects, like so::

    import pem

    myPems = []
    pems = pem.parse("""\
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
    """)

    ctxFactory = pem.certificateOptionsFromPEMs(pems)


Ephemeral Diffie-Hellman support
--------------------------------

Starting with version 14.0.0, Twisted will support ephemeral Diffie-Hellman ciphersuites; you can pass an instance of ``twisted.internet.ssl.DiffieHellmanParameters`` as the ``dhParameters`` keyword argument to ``CertificateOptions``.
Since ``pem`` just passes keyword arguments to ``CertificateOptions`` verbatim, that will just work.

However, ``pem`` is also forward compatible.
If your version of Twisted predates 14.0.0, ``pem`` lets you use the API described above anyway.
You can just use ``pem.DiffieHellmanParameters``: if your version of Twisted comes with that class, you just get the Twisted version; if it doesn't, you get a version from ``pem``.

Just pass instances of that class as ``dhParameters`` to ``certificateOptionsFromFiles``, and ``pem`` will make it magically work:

.. code-block:: python

   import pem

   from twisted.python.filepath import FilePath

   path = FilePath("/path/to/the/dh/params")
   ctxFactory = pem.certificateOptionsFromFiles(
      'key.pem', 'cert_and_chain.pem',
      dhParameters=pem.DiffieHellmanParameters.fromFile(path)
   )

.. _CertificateOptions: https://twistedmatrix.com/documents/current/api/twisted.internet.ssl.CertificateOptions.html

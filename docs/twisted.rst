Twisted
=======

A typical use case in Twisted with the core API would be::

   import pem

   from twisted.internet import ssl

   key = pem.parse_file("key.pem")
   cert, chain = pem.parse_file("cert_and_chain.pem")
   cert = ssl.PrivateCertificate.loadPEM(str(key) + str(cert))
   chainCert = ssl.Certificate.loadPEM(str(chain))
   dhParams = ssl.DiffieHellmanParameters(str(pem.parse_file("dhparams.pem")))

   ctxFactory = ssl.CertificateOptions(
         privateKey=cert.privateKey.original,
         certificate=cert.original,
         extraCertChain=[chainCert.original],
         dhParameters=dhParams,
   )

Turns out, this is a major use case.
Therefore it can be simplified to::

   ctxFactory = pem.twisted.certificateOptionsFromFiles(
      "key.pem", "cert_and_chain.pem", "dhparams.pem",
   )


There must be exactly one private key present.
The certificate matching the private key will be used as the server certificate, the rest is passed as the chain.
There must be no more than one set of DH parameters.
You can pass as many PEM files as you like.
Therefore you can distribute your key, certificate, chain certificates, and DH parameters over a arbitrary number of files.
A ``ValueError`` is raised if more than one key, no key, or no certificate are found.
Any further keyword arguments will be passed to CertificateOptions_.
Passing ``dhParameters`` as a keyword argument is deprecated; pass these as a PEM object instead.

If you want to load your PEM data from somewhere else, you can also use
:func:`pem.twisted.certificateOptionsFromPEMs` to do the same thing with already-loaded PEM objects, like so::

    myPems = []
    pems = pem.parse("""\
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
    """)

    ctxFactory = pem.twisted.certificateOptionsFromPEMs(pems)


Ephemeral Diffie-Hellman support
--------------------------------

.. warning::
   This feature is deprecated and will be removed a year after the release of 15.0.0.

Starting with version 14.0.0, Twisted supports ephemeral Diffie-Hellman ciphersuites.
You can pass an instance of ``twisted.internet.ssl.DiffieHellmanParameters`` as the ``dhParameters`` keyword argument to ``CertificateOptions``.
Since ``pem`` just passes keyword arguments to ``CertificateOptions`` verbatim, that will just work.

However, ``pem`` is also forward compatible.
If your version of Twisted predates 14.0.0, ``pem`` lets you use the API described above anyway.
You can just use ``pem.twisted.DiffieHellmanParameters``: if your version of Twisted comes with that class, you just get the Twisted version; if it doesn't, you get a version from ``pem``.

Just pass instances of that class as ``dhParameters`` to ``certificateOptionsFromFiles``, and ``pem`` will make it magically work::

   import pem

   from twisted.python.filepath import FilePath

   path = FilePath("/path/to/the/dh/params")
   ctxFactory = pem.twisted.certificateOptionsFromFiles(
      'key.pem', 'cert_and_chain.pem',
      dhParameters=pem.DiffieHellmanParameters.fromFile(path)
   )

.. _CertificateOptions: https://twistedmatrix.com/documents/current/api/twisted.internet.ssl.CertificateOptions.html

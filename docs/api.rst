.. _api:

API Reference
=============


Core
----

.. currentmodule:: pem

See :doc:`core` for examples.

Parsers
^^^^^^^

.. autofunction:: parse

.. autofunction:: parse_file


.. _pem-objects:

PEM Objects
^^^^^^^^^^^

The following objects can be returned by the parsing functions.

.. autoclass:: Certificate(AbstractPEMObject)
.. autoclass:: OpenSSLTrustedCertificate(Certificate)
.. autoclass:: Key(AbstractPEMObject)
.. autoclass:: PrivateKey(Key)
.. autoclass:: PublicKey(Key)
.. autoclass:: RSAPrivateKey(PrivateKey)
.. autoclass:: RSAPublicKey(PublicKey)
.. autoclass:: ECPrivateKey(PrivateKey)
.. autoclass:: DSAPrivateKey(PrivateKey)
.. autoclass:: OpenSSHPrivateKey(PrivateKey)
.. autoclass:: SSHPublicKey(Key)
.. autoclass:: SSHCOMPrivateKey(PrivateKey)
.. autoclass:: OpenPGPPublicKey(PublicKey)
.. autoclass:: OpenPGPPrivateKey(PrivateKey)
.. autoclass:: DHParameters(AbstractPEMObject)
.. autoclass:: CertificateRequest(AbstractPEMObject)
.. autoclass:: CertificateRevocationList(AbstractPEMObject)

Their shared provided API is minimal:

.. autoclass:: AbstractPEMObject
   :members: __str__, as_bytes, as_text, sha1_hexdigest, payload_as_bytes, payload_as_text


Twisted
-------

.. currentmodule:: pem.twisted

See :doc:`twisted` for examples.

.. autofunction:: certificateOptionsFromFiles
.. autofunction:: certificateOptionsFromPEMs

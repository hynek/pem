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
The provided API is minimal:
they can be transformed using ``str(obj)`` into a PEM string (of type ``str``),
and they can be transformed into bytes using ``obj.as_bytes()``.

The ``repr`` methods of the objects contain a SHA-1 hash digest of the PEM string.
The sole purpose of this digest is to keep objects from each other without printing the actual (long) PEM string.

.. autoclass:: Certificate()
.. autoclass:: Key()
.. autoclass:: RSAPrivateKey(Key)
.. autoclass:: DHParameters()


Twisted
-------

.. currentmodule:: pem.twisted

See :doc:`twisted` for examples.

.. autofunction:: certificateOptionsFromFiles
.. autofunction:: certificateOptionsFromPEMs

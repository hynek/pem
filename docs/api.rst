.. _api:

API
===


Core
----

.. currentmodule:: pem

See :doc:`core` for examples.

Parsers
^^^^^^^

.. autofunction:: parse

.. autofunction:: parse_file


PEM Objects
^^^^^^^^^^^

The following objects can be returned by the parsing functions.
They have *no public API* except that they can be transformed using ``str(obj)`` into a PEM string.

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

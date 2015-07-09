Core API
========

The core API call is the function ``parse()``::

   import pem

   with open('cert.pem', 'rb') as f:
      certs = pem.parse(f.read())

The function returns a list of valid PEM objects found in the string supplied.
Currently possible types are ``DHParameters``, ``Certificate``, and ``RSAPrivateKey``.
Both can be transformed using ``str()`` into plain strings for other APIs.
They don’t offer any other public API at the moment.


Convenience
-----------

Since ``pem`` is mostly a convenience module, there are several helper functions.


Files
^^^^^

``parse_file(file_name)`` reads the file ``file_name`` and parses its contents.
So the following example is equivalent with the first one::

   import pem

   certs = pem.parse_file('cert.pem')

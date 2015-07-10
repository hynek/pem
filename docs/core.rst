Core API
========

The core API call is the function :func:`pem.parse`::

   import pem

   with open("cert.pem", "rb") as f:
      certs = pem.parse(f.read())

The function returns a list of valid :ref:`PEM objects <pem-objects>` found in the string supplied.
Both can be transformed using ``str()`` into plain strings for other APIs.
They don’t offer any other public API at the moment.


Files
^^^^^

For convenience, there's the helper function :func:`pem.parse_file` that reads a file and parses its contents.
So the following example is equivalent with the first one::

   certs = pem.parse_file("cert.pem")

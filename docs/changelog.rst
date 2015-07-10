.. :changelog:

Changelog
=========

Please refer to :doc:`backward-compatibility` for details on deprecations and backward-incompatible changes.


15.0.0 (UNRELEASED)
-------------------


Backward-incompatible changes:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

*none*


Deprecations:
^^^^^^^^^^^^^

- The usage of Twisted helpers from the pem module is deprecated.
  Use their pendants from the ``pem.twisted`` module now.
- The usage of the backport of ephemeral Diffie-Hellman support is hereby deprecated.
  Nobody should use a Twisted release that is older than 14.0.0 because it contains essential SSL/TLS fixes.


Changes:
^^^^^^^^

- Support PEM strings that do not end with a new line. [`12 <https://github.com/hynek/pem/pull/12>`_]
- Support PEM strings that end with ``\r\n``.
- The Twisted-related helpers have been moved to ``pem.twisted``.


0.3.0 (2014-04-15)
------------------

- Load PEM files as UTF-8 to allow for non-ASCII comments (like in certifi).
- Allow keys, primary certificates, and chain certificates to occur in any order.


0.2.0 (2014-03-13)
------------------

- Add forward-compatible support for DHE.


0.1.0 (2013-07-18)
------------------

- Initial release.

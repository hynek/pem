.. :changelog:

Changelog
=========

15.0.0 (UNRELEASED)
-------------------


Backward-incompatible changes:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

*none*


Deprecations:
^^^^^^^^^^^^^

*none*

Changes:
^^^^^^^^

- Support PEM strings that do not end with a new line. [`12 <https://github.com/hynek/pem/pull/12>`_]


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

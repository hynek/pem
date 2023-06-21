# Changelog

All notable changes to this project will be documented in this file.

The format is based on [*Keep a Changelog*](https://keepachangelog.com/en/1.0.0/) and this project adheres to [*Calendar Versioning*](https://calver.org/).

The **first number** of the version is the year.
The **second number** is incremented with each release, starting at 1 for each year.
The **third number** is for emergencies when we need to start branches for older releases.

You can find our backwards-compatibility policy [here](https://github.com/hynek/pem/blob/main/.github/SECURITY.md).

<!-- changelog follows -->

## [23.1.0](https://github.com/hynek/pem/compare/21.2.0...23.1.0) - 2023-06-21

### Removed

- Support for Python 2.7, 3.5, and 3.6 has been dropped.


### Added

- Support for RFC 4880 OpenPGP private & public keys: `pem.OpenPGPPublicKey` and `pem.OpenPGPPrivateKey`.
  [#72](https://github.com/hynek/pem/issues/72)
- Support for intra-payload headers like the ones used in OpenPGP keys using the `meta_headers` property.
  [#75](https://github.com/hynek/pem/pull/75)
- `pem.parse_file()` now accepts also [`pathlib.Path`](https://docs.python.org/3/library/pathlib.html#pathlib.Path) objects.
- `pem.parse()` now also accepts `str`.
- Added `text_payload`, `bytes_payload` and `decoded_payload` properties to all PEM objects that allow to directly access the payload without the envelope and possible headers.
  [#74](https://github.com/hynek/pem/pull/74)


## [21.2.0](https://github.com/hynek/pem/compare/21.1.0...21.2.0) - 2021-04-07

### Added

- Added support for `pem.OpenSSLTrustedCertificate` (`-----BEGIN TRUSTED CERTIFICATE-----`), as defined in [openssl x509 manual](https://www.openssl.org/docs/man1.1.1/man1/x509.html).
  [#28](https://github.com/hynek/pem/issues/28)


## [21.1.0](https://github.com/hynek/pem/compare/20.1.0...21.1.0) - 2021-01-22

### Added

- Added support for DSA private keys (`BEGIN DSA PRIVATE`).
  This is also the OpenSSH legacy PEM format.
  [#49](https://github.com/hynek/pem/issues/49)
- Added support for `pem.SSHPublicKey` (`---- BEGIN SSH2 PUBLIC KEY ----`), as defined in [RFC 4716](https://datatracker.ietf.org/doc/html/rfc4716).
  [#46](https://github.com/hynek/pem/pull/46)
- Added support for `pem.SSHCOMPrivateKey` (`---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----`), the SSH.com / Tectia private key format (plain or encrypted).
  [#46](https://github.com/hynek/pem/pull/46)


## [20.1.0](https://github.com/hynek/pem/compare/19.3.0...20.1.0) - 2020-01-06

### Changed

- Carriage returns (`\r`) are now stripped before hashing *pem* objects to provide consistent hashes across platforms.
  [#40](https://github.com/hynek/pem/issues/40)


## [19.3.0](https://github.com/hynek/pem/compare/19.2.0...19.3.0) - 2019-10-16

### Removed

- Python 3.4 is not supported anymore.
  It has been unsupported by the Python core team for a while now and its PyPI downloads are negligible.

  It's very unlikely that *pem* will break under 3.4 anytime soon, but we don't test it anymore.

### Added

- Added support for `pem.OpenSSHPrivateKey` (`OPENSSH PRIVATE KEY`).
  OpenSSH added a new `BEGIN` label when it switched to a proprietary key encoding.
  [#39](https://github.com/hynek/pem/pull/39)


## [19.2.0](https://github.com/hynek/pem/compare/19.1.0...19.2.0) - 2019-08-06

### Added

- Added support for `pem.ECPrivateKey` (`EC PRIVATE KEY`).


## [19.1.0](https://github.com/hynek/pem/compare/18.2.0...19.1.0) - 2019-03-19

### Added

- You can now load encrypted PKCS#8 PEM key as `pem.Key`.
- Added support for `pem.PublicKey` (`PUBLIC KEY`).
- Added support for `pem.RSAPublicKey` (`RSA PUBLIC KEY`).


## [18.2.0](https://github.com/hynek/pem/compare/18.1.0...18.2.0) - 2018-10-09

### Added

- Added `pem.CertificateRevocationList` for certificate revocation lists (CRLs).
  [#32](https://github.com/hynek/pem/pull/32)


## [18.1.0](https://github.com/hynek/pem/compare/17.1.0...18.1.0) - 2018-06-23

### Removed

- `pem.certificateOptionsFromFiles()` and `pem.certificateOptionsFromPEMs()` have been removed after three years of deprecation.
  Please use `pem.twisted.certificateOptionsFromFiles()` `pem.twisted.certificateOptionsFromPEMs()` instead.
- Diffie-Hellman support for Twisted older than 14.0 has been removed.


### Added

- *pem* now ships with typing information that can be used by type checkers like [Mypy](https://mypy-lang.org).
- PEM objects now have an `obj.sha1_hexdigest` property with the SHA-1 digest of the stored bytes  as a native string.
  This is the same digest as the one that is used by the PEM objects' `__repr__`s.
- PEM objects now have an `obj.as_text()` method that returns the PEM-encoded content as unicode, always.


## [17.1.0](https://github.com/hynek/pem/compare/16.1.0...17.1.0) - 2017-08-10

### Added

- Added `pem.CertificateRequest` for [certificate signing requests](https://en.wikipedia.org/wiki/Certificate_signing_request).
  [#29](https://github.com/hynek/pem/pull/29)


## [16.1.0](https://github.com/hynek/pem/compare/16.0.0...16.1.0) - 2016-04-08

### Deprecated

- Passing `dhParameters` to `pem.twisted.certifateOptionsFromPEMs` and `certificateOptionsFromFiles` is now deprecated;
  instead, include the DH parameters in the PEM objects or files.

### Removed

- Python 3.3 and 2.6 aren't supported anymore.
  They may work by chance but any effort to keep them working has ceased.

  The last Python 2.6 release was on October 29, 2013 and isn't supported by the CPython core team anymore.
  Major Python packages like Django and Twisted dropped Python 2.6 a while ago already.

  Python 3.3 never had a significant user base and wasn't part of any distribution's LTS release.

### Added

- `pem.twisted.certificateOptionsFromPEMs` and `certificateOptionsFromFiles` will now load Ephemeral Diffie-Hellman parameters if found.
  [#21](https://github.com/hynek/pem/pull/21)
- PEM objects now have an `as_bytes` method that returns the PEM-encoded content as bytes, always.
  [#24](https://github.com/hynek/pem/pull/24)


### Fixed

- PEM objects now correctly handle being constructed with unicode and bytes on both Python 2 and 3.
  [#24](https://github.com/hynek/pem/pull/24)
- PEM objects are now hashable and comparable for equality.
  [#25](https://github.com/hynek/pem/pull/25)


## [16.0.0](https://github.com/hynek/pem/compare/15.0.0...16.0.0) - 2016-02-05

### Added

- PKCS #8 keys are now supported.
  [#14](https://github.com/hynek/pem/pull/14)
- *pem* is now fully functional without installing Twisted.
  [#16](https://github.com/hynek/pem/pull/16)


## [15.0.0](https://github.com/hynek/pem/compare/0.3.0...15.0.0) - 2015-07-10

### Deprecated

- The usage of Twisted helpers from the pem module is deprecated.
  Use their pendants from the `pem.twisted` module now.
- The usage of the backport of ephemeral Diffie-Hellman support is hereby deprecated.
  Nobody should use a Twisted release that is older than 14.0.0 because it contains essential SSL/TLS fixes.

### Changed

- Support PEM strings that do not end with a new line.
  [#12](https://github.com/hynek/pem/pull/12)
- Support PEM strings that end with `\r\n`.
- The Twisted-related helpers have been moved to `pem.twisted`.


## [0.3.0](https://github.com/hynek/pem/compare/0.2.0...0.3.0) - 2014-04-15

### Changed

- Load PEM files as UTF-8 to allow for non-ASCII comments (like in *certifi*).
- Allow keys, primary certificates, and chain certificates to occur in any order.


## [0.2.0](https://github.com/hynek/pem/compare/v0.1.0...0.2.0) - 2014-03-13

### Added

- Add forward-compatible support for DHE.


## [0.1.0](https://github.com/hynek/pem/tree/v0.1.0) - 2013-07-18

Initial release.

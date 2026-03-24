# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [6.10.0](https://github.com/node-opcua/node-opcua-pki/compare/v6.9.0...v6.10.0) (2026-03-24)


### Bug Fixes

* **ca:** use `keyid` instead of `keyid:always,issuer:always` ([72e6f8d](https://github.com/node-opcua/node-opcua-pki/commit/72e6f8dca5ea3a73602b0c36d3d9455223279a73))





# [6.9.0](https://github.com/node-opcua/node-opcua-pki/compare/v6.8.2...v6.9.0) (2026-03-20)


### Bug Fixes

* **ca:** revokeCertificateDER now uses stored cert ([ecde299](https://github.com/node-opcua/node-opcua-pki/commit/ecde2991f8b3ad4c324980daafa9b0527c5d7ded))
* strip OpenSSL text dump from PEM accessors ([65f4474](https://github.com/node-opcua/node-opcua-pki/commit/65f447431b9f250a924d0b91cd2ea86dcb631f1f))


### Features

* **ca:** add buffer-based cert & CRL accessors ([641e482](https://github.com/node-opcua/node-opcua-pki/commit/641e482373831a5c7065f2df26bd2df91ab106e6))
* **ca:** add buffer-based sign & revoke methods ([aa1b0ac](https://github.com/node-opcua/node-opcua-pki/commit/aa1b0acf8564a78c51c27dd31982274f32ae238f))
* **ca:** add certificate database API (US-057) ([cc01917](https://github.com/node-opcua/node-opcua-pki/commit/cc01917efa90e2bbb6151c5fc2e30dcf7cd6860a))





## [6.8.2](https://github.com/node-opcua/node-opcua-pki/compare/v6.8.1...v6.8.2) (2026-03-08)


### Features

* **pki:** add isTrustListEmpty() and ([227a95d](https://github.com/node-opcua/node-opcua-pki/commit/227a95de56baccb9d5cdb64fe7fb32bc06fc7ac4))





## [6.8.1](https://github.com/node-opcua/node-opcua-pki/compare/v6.8.0...v6.8.1) (2026-03-07)

**Note:** Version bump only for package node-opcua-pki





# [6.8.0](https://github.com/node-opcua/node-opcua-pki/compare/v6.7.3...v6.8.0) (2026-03-03)

**Note:** Version bump only for package node-opcua-pki





## [6.7.3](https://github.com/node-opcua/node-opcua-pki/compare/v6.7.2...v6.7.3) (2026-03-02)


### Bug Fixes

* drain pending locks in CertificateManager.dispose() ([0b546dd](https://github.com/node-opcua/node-opcua-pki/commit/0b546dd499e2ea15296c3e0dba3704f4a1813fc4))





## [6.7.2](https://github.com/node-opcua/node-opcua-pki/compare/v6.7.1...v6.7.2) (2026-03-01)


### Bug Fixes

* prevent EPERM crash on Windows + Node < 22 ([9fef706](https://github.com/node-opcua/node-opcua-pki/commit/9fef706f5e78da7c4c99bd0d3f92c34bfd36e27e))





## [6.7.1](https://github.com/node-opcua/node-opcua-pki/compare/v6.7.0...v6.7.1) (2026-02-27)


### Bug Fixes

* **certificate-manager:** avoid double .lock suffix ([f161ff2](https://github.com/node-opcua/node-opcua-pki/commit/f161ff23ef0d447dab388458db9222c144683294))


### Performance Improvements

* **certificate-manager:** add LRU cache for ([f0e9126](https://github.com/node-opcua/node-opcua-pki/commit/f0e9126ab362cad68210c1047da08e4bc73eec33))





# [6.7.0](https://github.com/node-opcua/node-opcua-pki/compare/v6.6.0...v6.7.0) (2026-02-26)


### Bug Fixes

* emit certificateAdded for certs written before ([e229161](https://github.com/node-opcua/node-opcua-pki/commit/e2291618ef8d8701fb0053ccdfa480990d508150))
* macOS CI test failures for stale issuer index ([610e54f](https://github.com/node-opcua/node-opcua-pki/commit/610e54ff64f9a4f682349fb9050e5897af454b1a))





# [6.6.0](https://github.com/node-opcua/node-opcua-pki/compare/v6.5.1...v6.6.0) (2026-02-26)


### Features

* deferred watcher init and event emission ([f813c6f](https://github.com/node-opcua/node-opcua-pki/commit/f813c6f26c2c6fca16e7e0bad6999dcd748d5664))





## [6.5.1](https://github.com/node-opcua/node-opcua-pki/compare/v6.5.0...v6.5.1) (2026-02-23)

**Note:** Version bump only for package node-opcua-pki





# [6.5.0](https://github.com/node-opcua/node-opcua-pki/compare/v6.4.0...v6.5.0) (2026-02-22)


### Bug Fixes

* keep fs.watch interception until chokidar ready event and add before/after checkAllDisposed guards ([6fef633](https://github.com/node-opcua/node-opcua-pki/commit/6fef633a26168e6fd6478dde2cb0bd46906384ff))
* prevent undisposed CertificateManager from blocking ([0fbe111](https://github.com/node-opcua/node-opcua-pki/commit/0fbe111a2eb68b6e53fb5db9cbc711b09265d21c))


* refactor!: sanitize public API and add JSDoc documentation ([ff8903f](https://github.com/node-opcua/node-opcua-pki/commit/ff8903fa3929782c6dd732583b6965e353ad5057))


### Features

* **pki:** Enhance PFX toolbox and certificate verification ([a81b9c9](https://github.com/node-opcua/node-opcua-pki/commit/a81b9c9dbed9743218b21865e134a71183bcc4f0)), closes [PKCS#12](https://github.com/PKCS/issues/12)


### BREAKING CHANGES

* `pki_main` is no longer exported from the
public API. The CLI binary now imports it directly from the
internal module.

- remove `pki_main` from public API (index.ts); the CLI
  (`bin/pki.ts`) now imports directly from internal path
- remove internal helpers from public API: `g_config`,
  `mkdirRecursiveSync`, `warningLog`, `makePath`, `quote`
- move `Params` type import to internal path in tests
- update all test imports to use `node-opcua-pki-priv/...`
  paths for internal symbols
- fix `reloadCertificates` tests that incorrectly disabled
  `untrustUnknownCertificate` (causing false "Good" status)

- add comprehensive JSDoc to `CertificateAuthority` class,
  `CertificateAuthorityOptions`, and all public members
- add comprehensive JSDoc to `CertificateManager` class,
  all public/protected methods, getters, fields, and the
  `findIssuerCertificateInChain` standalone function
- add JSDoc to all exported types and interfaces in
  `common.ts`: `KeySize`, `Filename`, `CertificateStatus`,
  `ProcessAltNamesParam`, `Params`, `StartDateEndDateParam`,
  `CreateSelfSignCertificateParam`, etc.
- add JSDoc to `CertificateManagerOptions`,
  `CreateSelfSignCertificateParam1`,
  `VerifyCertificateOptions`, `VerificationStatus`,
  `CertificateManagerState`
- mark `KeyLength` as @deprecated in favor of `KeySize`
- clean up old-style `@method`/`@async` JSDoc tags





# [6.4.0](https://github.com/node-opcua/node-opcua-pki/compare/v6.3.0...v6.4.0) (2026-02-20)


### Bug Fixes

* add mutex to _moveCertificate, fix dispose ([32b76b5](https://github.com/node-opcua/node-opcua-pki/commit/32b76b560848e9b94baa8ebccb0e5122aa32f919))
* **CertificateManager:** scan issuers folder from disk ([25a8c15](https://github.com/node-opcua/node-opcua-pki/commit/25a8c15c28c0215d8df072e68e42473734dff0b0))


### Features

* **CertificateManager:** add reloadCertificates and ([033204c](https://github.com/node-opcua/node-opcua-pki/commit/033204cb3ae77c1438143e3cd82467f779a928b8))


### Performance Improvements

* cache exploreCertificate results in Entry ([9956ecf](https://github.com/node-opcua/node-opcua-pki/commit/9956ecfbcd2cea2bed2c4d1ef16bdddc8c35802f))





# [6.3.0](https://github.com/node-opcua/node-opcua-pki/compare/v6.2.0...v6.3.0) (2026-02-20)


### Bug Fixes

* **CertificateManager:** use lightweight chain validation ([ec3850f](https://github.com/node-opcua/node-opcua-pki/commit/ec3850f807a387d8932dfd92ced1be9ccabd17ee))





# [6.2.0](https://github.com/node-opcua/node-opcua-pki/compare/v6.1.0...v6.2.0) (2026-02-20)


### Features

* **CertificateManager:** add certificate management and validation API ([d0c6ceb](https://github.com/node-opcua/node-opcua-pki/commit/d0c6cebb3897ae9e40f6aaeb8a619c2f7b783073))





# [6.1.0](https://github.com/node-opcua/node-opcua-pki/compare/v6.0.0...v6.1.0) (2026-02-20)

**Note:** Version bump only for package node-opcua-pki





# [6.0.0](https://github.com/node-opcua/node-opcua-pki/compare/v1.1.0...v6.0.0) (2026-02-20)


### Bug Fixes

* resolve test failures after monorepo restructuring ([747fc75](https://github.com/node-opcua/node-opcua-pki/commit/747fc75c8be09104fb43cc37fc3d9803dc8788e2))
* update test imports for monorepo structure ([5cc9ebe](https://github.com/node-opcua/node-opcua-pki/commit/5cc9ebe90ca39b0c45163597c2aed500f07d5431))

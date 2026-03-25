# CertificateManager API

The `CertificateManager` manages an OPC UA–compliant PKI directory
structure with trust stores, issuer stores, and certificate lifecycle
management.

## Table of Contents

- [Quick Start](#quick-start)
- [Constructor Options](#constructor-options)
- [Certificate Trust](#certificate-trust)
- [Issuer (CA) Certificates](#issuer-ca-certificates)
- [Certificate Revocation Lists](#certificate-revocation-lists)
- [File Watching](#file-watching)
- [Events](#events)
- [Folder Accessors](#folder-accessors)

---

## Quick Start

```typescript
import { CertificateManager } from "node-opcua-pki";

const cm = new CertificateManager({
    location: "./my_pki",
    keySize: 2048,
});

await cm.initialize();

// Create a self-signed certificate
await cm.createSelfSignedCertificate({
    applicationUri: "urn:my-server:application",
    subject: "/CN=My Server/O=My Organization",
    dns: ["localhost"],
    startDate: new Date(),
    validity: 365,
});
```

---

## Constructor Options

| Option     | Type                       | Description                            |
| ---------- | -------------------------- | -------------------------------------- |
| `location` | `string`                   | PKI directory path                     |
| `keySize`  | `1024\|2048\|3072\|4096`   | RSA key size (default: `2048`)         |

---

## Certificate Trust

| Method                                          | Description                                                    |
| ----------------------------------------------- | -------------------------------------------------------------- |
| `trustCertificate(cert)`                        | Add a certificate to the trusted store                         |
| `rejectCertificate(cert)`                       | Move a certificate to the rejected store                       |
| `verifyCertificate(cert, options?)`             | Full certificate chain validation                              |
| `removeTrustedCertificate(thumbprint)`          | Remove by SHA-1 thumbprint; returns the cert buffer or `null`  |
| `addTrustedCertificateFromChain(certChain)`     | Validate and trust the leaf certificate from a DER chain       |
| `isIssuerInUseByTrustedCertificate(issuerCert)` | Check if any trusted cert was signed by this issuer            |
| `reloadCertificates()`                          | Force a full re-scan of all PKI folders                        |

---

## Issuer (CA) Certificates

| Method                                        | Description                                                  |
| --------------------------------------------- | ------------------------------------------------------------ |
| `addIssuer(cert, validate?, addInTrustList?)` | Add a CA certificate to the issuers store                    |
| `hasIssuer(thumbprint)`                       | Check if an issuer exists by SHA-1 thumbprint                |
| `removeIssuer(thumbprint)`                    | Remove by thumbprint; returns the cert buffer or `null`      |
| `findIssuerCertificate(cert)`                 | Find the issuer certificate for a given certificate          |

---

## Certificate Revocation Lists

| Method                                          | Description                                                           |
| ----------------------------------------------- | --------------------------------------------------------------------- |
| `addRevocationList(crl, target?)`               | Add a CRL. `target`: `"issuers"` (default) or `"trusted"`            |
| `clearRevocationLists(target)`                  | Remove all CRLs from `"issuers"`, `"trusted"`, or `"all"`            |
| `removeRevocationListsForIssuer(cert, target?)` | Remove CRLs issued by a specific CA. `target`: `"all"` (default)     |
| `isCertificateRevoked(cert, issuerCert?)`       | Check if a certificate has been revoked                               |

---

## File Watching

`CertificateManager` uses [chokidar](https://github.com/paulmillr/chokidar)
to watch the PKI folders for changes. Native OS events are used by default.

### Environment Variables

| Variable                     | Description                                       | Default |
| ---------------------------- | ------------------------------------------------- | ------- |
| `OPCUA_PKI_USE_POLLING`      | `"true"` to use polling (NFS, Docker volumes)     | `false` |
| `OPCUA_PKI_POLLING_INTERVAL` | Polling interval in ms (clamped to [100, 600000]) | `5000`  |

```bash
# Example: enable polling with a 2-second interval
OPCUA_PKI_USE_POLLING=true OPCUA_PKI_POLLING_INTERVAL=2000 node my_server.js
```

> **Note:** If external processes modify the PKI folders directly
> (CLI tools, OPC UA `WriteTrustList`), call `reloadCertificates()`
> to force an immediate re-scan.

---

## Events

After `initialize()`, the `CertificateManager` emits events when
its file-system watchers detect live changes. Events are **not**
emitted during `initialize()` or `reloadCertificates()`.

| Event                | Payload                                           | Description                      |
| -------------------- | ------------------------------------------------- | -------------------------------- |
| `certificateAdded`   | `{ store, certificate, fingerprint, filename }`   | Certificate added to a store     |
| `certificateRemoved` | `{ store, fingerprint, filename }`                | Certificate removed from a store |
| `certificateChange`  | `{ store, certificate, fingerprint, filename }`   | Certificate modified in a store  |
| `crlAdded`           | `{ store, filename }`                             | CRL file added                   |
| `crlRemoved`         | `{ store, filename }`                             | CRL file removed                 |

`store` values: `"trusted"`, `"rejected"`, `"issuersCerts"`,
`"crl"`, `"issuersCrl"`

```typescript
cm.on("certificateAdded", ({ store, fingerprint }) => {
    console.log(`New certificate in ${store}: ${fingerprint}`);
});
```

---

## Folder Accessors

| Getter              | Path                       |
| ------------------- | -------------------------- |
| `trustedFolder`     | `{location}/trusted/certs` |
| `rejectedFolder`    | `{location}/rejected`      |
| `crlFolder`         | `{location}/trusted/crl`   |
| `issuersCertFolder` | `{location}/issuers/certs` |
| `issuersCrlFolder`  | `{location}/issuers/crl`   |
| `rootDir`           | `{location}`               |

---

## Directory Layout

```text
<location>/
  ├── issuers/
  │   ├── certs/       CA certificates
  │   └── crl/         Certificate Revocation Lists
  ├── own/
  │   ├── certs/       Generated public certificates
  │   └── private/
  │       └── private_key.pem
  ├── rejected/        Rejected certificates
  └── trusted/
      ├── certs/       Trusted X.509 v3 certificates
      └── crl/         CRLs for trusted certificates
```

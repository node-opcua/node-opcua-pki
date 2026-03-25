# CertificateAuthority API

The `CertificateAuthority` class manages an OpenSSL-based CA directory
structure for issuing, revoking, and tracking X.509 certificates.

## Table of Contents

- [Root CA (Self-Signed)](#root-ca-self-signed)
- [Intermediate CA (Subordinate)](#intermediate-ca-subordinate)
- [Signing End-Entity Certificates](#signing-end-entity-certificates)
- [Certificate Lifecycle](#certificate-lifecycle)
- [Buffer Accessors](#buffer-accessors)
- [Buffer Operations](#buffer-operations)
- [Certificate Database](#certificate-database)
- [Directory Layout](#directory-layout)

---

## Root CA (Self-Signed)

A root CA is the simplest setup — it signs its own certificate
automatically during `initialize()`.

```typescript
import { CertificateAuthority } from "node-opcua-pki";

const rootCA = new CertificateAuthority({
    keySize: 2048,
    location: "./my_root_ca",
    subject: "/CN=My Root CA/O=My Organization",
});
await rootCA.initialize();

// Ready to sign certificates immediately
```

### Constructor Options

| Option    | Type                         | Description                          |
| --------- | ---------------------------- | ------------------------------------ |
| `keySize`  | `1024\|2048\|3072\|4096` | RSA key size for the CA private key |
| `location`| `string`                     | Filesystem path for the CA directory |
| `subject` | `string \| SubjectOptions`   | X.500 subject (e.g. `"/CN=My CA"`)  |
| `issuerCA`| `CertificateAuthority?`      | Parent CA (omit for root CA)         |

---

## Intermediate CA (Subordinate)

An intermediate CA is signed by an external root CA. This enables a
**manual 3-step workflow** that supports external, third-party root CAs
you don't control.

### Workflow Overview

```text
┌─────────────────┐     CSR      ┌─────────────────┐
│ Intermediate CA │ ──────────►  │   Root CA       │
│ (your server)   │              │ (external/ours) │
│                 │  ◄────────── │                 │
│                 │  signed cert │                 │
└─────────────────┘  (+ chain)   └─────────────────┘
```

### Step 1: Generate CSR

```typescript
const intermediateCA = new CertificateAuthority({
    keySize: 2048,
    location: "./my_intermediate_ca",
    subject: "/CN=My Intermediate CA/O=My Organization",
});

const result = await intermediateCA.initializeCSR();
// result.status: "created" | "ready" | "pending" | "expired"

if (result.status === "created" || result.status === "expired") {
    // Send result.csrPath to the root CA for signing
    console.log("CSR ready at:", result.csrPath);
}
```

### Step 2: Root CA Signs the CSR

If the root CA is also a `CertificateAuthority` instance:

```typescript
// The output file automatically contains the full chain:
// [signedIntermediateCert, rootCACert]
await rootCA.signCACertificateRequest(
    outputCertFile,
    csrPath,
    { validity: 3650 }
);
```

If the root CA is external, you'll receive a PEM file
(possibly a chain) from their signing process.

### Step 3: Install the Signed Certificate

```typescript
const installResult = await intermediateCA.installCACertificate(
    signedCertFile  // single cert or chain [cert, issuer, ...]
);

if (installResult.status === "error") {
    console.error(installResult.message);
}
```

**What happens internally:**

- The first PEM block is verified against the CA private key
- First cert → `public/cacert.pem`
- Remaining issuer certs → `public/issuer_chain.pem`
- Initial CRL is generated

### `initializeCSR()` Return Values

| Status      | Meaning                                           | Action                          |
| ----------- | ------------------------------------------------- | ------------------------------- |
| `"ready"`   | Certificate exists and is valid                   | No action needed                |
| `"pending"` | Key + CSR exist, no cert (restart recovery)       | Re-submit CSR for signing       |
| `"created"` | Fresh key + CSR generated                         | Send CSR to root CA             |
| `"expired"` | Certificate expired; new CSR generated            | Send CSR to root CA for renewal |

### `installCACertificate()` Return Values

| Status    | Meaning                                  |
| --------- | ---------------------------------------- |
| `"success"` | Certificate installed, CRL generated |
| `"error"`   | Rejected — see `reason` and `message` |

Error reasons: `"certificate_key_mismatch"`, `"no_certificate_found"`

---

## Proactive Certificate Renewal

Use `renewCSR()` while the CA is running to detect upcoming expiry:

```typescript
// Check if cert expires within 30 days (default)
const result = await intermediateCA.renewCSR(30);

if (result.status === "expired") {
    // CSR generated at result.csrPath — send to root CA
    // Existing private key is preserved
}
```

The full runtime renewal flow:

```typescript
// 1. Detect expiry
const renewal = await intermediateCA.renewCSR(30);
if (renewal.status !== "expired") return; // not yet

// 2. Root CA re-signs the CSR (output includes chain)
await rootCA.signCACertificateRequest(
    renewedCertFile, renewal.csrPath, { validity: 3650 }
);

// 3. Install renewed certificate
await intermediateCA.installCACertificate(renewedCertFile);

// 4. CA continues signing with the new certificate
//    (private key preserved → old end-entity certs stay valid)
```

---

## Signing End-Entity Certificates

### From a CSR File

```typescript
await ca.signCertificateRequest(outputCertFile, csrFile, {
    applicationUri: "urn:my-app",
    dns: ["app.example.com"],
    validity: 365,
});
// outputCertFile contains: [endEntityCert, caCert, issuerChain...]
```

### Generate Key + Sign in One Step

```typescript
const result = await ca.generateKeyPairAndSignDER({
    applicationUri: "urn:my-app",
    dns: ["app.example.com"],
    subject: "/CN=My App",
    validity: 365,
});
// result.certificateDer — DER buffer with full chain
// result.privateKey — the generated private key
```

### Certificate Chain Format

Per **OPC UA Part 6 §6.2.6**, the output follows:

```text
[endEntityCert, issuerCA, ..., rootCA (optional)]
```

When issuer chain information is available (via `installCACertificate`),
the full chain is produced automatically.

---

## Buffer Accessors

| Method                  | Returns  | Description                        |
| ----------------------- | -------- | ---------------------------------- |
| `getCACertificateDER()` | `Buffer` | CA certificate as DER              |
| `getCACertificatePEM()` | `string` | CA certificate as PEM              |
| `getCRLDER()`           | `Buffer` | Current CRL as DER (empty if none) |
| `getCRLPEM()`           | `string` | Current CRL as PEM                 |

## Buffer Operations

| Method                                    | Returns          | Description                                          |
| ----------------------------------------- | ---------------- | ---------------------------------------------------- |
| `signCertificateRequestFromDER(csr, opt)` | `Promise<Buffer>`| Sign a DER-encoded CSR, return signed cert as DER    |
| `revokeCertificateDER(cert, reason?)`     | `Promise<void>`  | Revoke a DER-encoded certificate                     |

```typescript
// Sign a CSR from a DER buffer
const certDer = await ca.signCertificateRequestFromDER(csrDer, {
    validity: 365,
});

// Revoke a certificate from its DER buffer
await ca.revokeCertificateDER(certDer, "keyCompromise");
```

---

## Certificate Database

These methods parse the OpenSSL `index.txt` database.

| Method                           | Returns                     | Description                         |
| -------------------------------- | --------------------------- | ----------------------------------- |
| `getIssuedCertificates()`        | `IssuedCertificateRecord[]` | All records from `index.txt`        |
| `getIssuedCertificateCount()`    | `number`                    | Total number of issued certificates |
| `getCertificateStatus(serial)`   | `string \| undefined`       | `"valid"`, `"revoked"`, `"expired"` |
| `getCertificateBySerial(serial)` | `Buffer \| undefined`       | DER buffer from `certs/<serial>.pem`|

**`IssuedCertificateRecord`** fields:

| Field            | Type                                | Description                 |
| ---------------- | ----------------------------------- | --------------------------- |
| `serial`         | `string`                            | Hex serial (e.g. `"1000"`)  |
| `status`         | `"valid" \| "revoked" \| "expired"` | Certificate status          |
| `subject`        | `string`                            | X.500 subject               |
| `expiryDate`     | `string`                            | ISO-8601 expiry date        |
| `revocationDate` | `string?`                           | ISO-8601 revocation date    |

---

## Path Accessors

| Getter                    | Path                          |
| ------------------------- | ----------------------------- |
| `caCertificate`           | `public/cacert.pem`           |
| `issuerCertificateChain`  | `public/issuer_chain.pem`     |
| `revocationList`          | `crl/revocation_list.pem`     |
| `revocationListDER`       | `crl/revocation_list.der`     |
| `caCertificateWithCrl`    | `public/cacert_with_crl.pem`  |
| `configFile`              | `conf/caconfig.cnf`           |
| `rootDir`                 | `<location>`                  |

---

## Directory Layout

```text
<location>/
  ├── conf/           OpenSSL configuration
  ├── private/        CA private key (cakey.pem)
  ├── public/         CA certificate (cacert.pem)
  │                   + issuer chain (issuer_chain.pem)
  ├── certs/          Issued certificates
  ├── crl/            Certificate Revocation Lists
  ├── index.txt       OpenSSL certificate database
  └── serial          Next serial number
```

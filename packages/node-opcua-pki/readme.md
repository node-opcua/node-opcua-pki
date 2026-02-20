# node-opcua-pki

[![NPM download](https://img.shields.io/npm/dm/node-opcua-pki.svg)](https://www.npmtrends.com/node-opcua-pki)
[![NPM version](https://img.shields.io/npm/v/node-opcua-pki)](https://www.npmjs.com/package/node-opcua-pki?activeTab=versions)
[![install size](https://packagephobia.com/badge?p=node-opcua-pki)](https://packagephobia.com/result?p=node-opcua-pki)

**PKI management for [node-opcua](https://node-opcua.github.io/)** — create and manage OPC UA certificates, Certificate Authorities, and Public Key Infrastructures.

## Quick Start

```bash
# Use directly with npx (no install needed)
npx node-opcua-pki --help
npx node-opcua-pki createPKI
npx node-opcua-pki certificate --selfSigned -o my_cert.pem

# Or install globally
npm install -g node-opcua-pki
pki --help
```

## Prerequisites

This module requires **OpenSSL** or **LibreSSL**:

| Platform          | Installation                          |
| ----------------- | ------------------------------------- |
| **Windows**       | Automatically downloaded at first run |
| **Ubuntu/Debian** | `apt install openssl`                 |
| **Alpine**        | `apk add openssl`                     |
| **macOS**         | Pre-installed (LibreSSL)              |

## CLI Commands

| Command              | Description                                      |
| -------------------- | ------------------------------------------------ |
| `demo`               | Create default certificates for node-opcua demos |
| `createCA`           | Create a Certificate Authority                   |
| `createPKI`          | Create a Public Key Infrastructure               |
| `certificate`        | Create a new certificate                         |
| `revoke <file>`      | Revoke an existing certificate                   |
| `csr`                | Create a certificate signing request (CSR)       |
| `sign`               | Sign a CSR and generate a certificate            |
| `dump <file>`        | Display a certificate                            |
| `toder <file>`       | Convert a certificate to DER format              |
| `fingerprint <file>` | Print the certificate fingerprint                |
| `version`            | Display the version number                       |

See also: [OPC Foundation GDS spec](https://reference.opcfoundation.org/GDS/docs/F.1/)

---

### createPKI

Create a Public Key Infrastructure directory structure.

```bash
pki createPKI [options]
```

| Option          | Description                                       | Default              |
| --------------- | ------------------------------------------------- | -------------------- |
| `-r, --root`    | Certificate folder location                       | `{CWD}/certificates` |
| `--PKIFolder`   | PKI folder location                               | `{root}/PKI`         |
| `-k, --keySize` | Private key size in bits (1024\|2048\|3072\|4096) | `2048`               |
| `-s, --silent`  | Minimize output                                   | `false`              |

**Generated structure:**

```
📂 certificates/PKI
├── 📂 issuers
│   ├── 📂 certs       CA certificates
│   └── 📂 crl         Certificate Revocation Lists
├── 📂 own
│   ├── 📂 certs       Generated public certificates
│   └── 📂 private
│       └── 🔐 private_key.pem
├── 📂 rejected        Rejected certificates
└── 📂 trusted
    ├── 📂 certs       Trusted X.509 v3 certificates
    └── 📂 crl         CRLs for trusted certificates
```

---

### createCA

Create a Certificate Authority.

```bash
pki createCA [options]
```

| Option           | Description                 | Default                                                                         |
| ---------------- | --------------------------- | ------------------------------------------------------------------------------- |
| `--subject`      | CA certificate subject      | `/C=FR/ST=IDF/L=Paris/O=Local NODE-OPCUA Certificate Authority/CN=NodeOPCUA-CA` |
| `-r, --root`     | Certificate folder location | `{CWD}/certificates`                                                            |
| `-c, --CAFolder` | CA folder location          | `{root}/CA`                                                                     |
| `-k, --keySize`  | Private key size in bits    | `2048`                                                                          |

---

### certificate

Create a new certificate (CA-signed or self-signed).

```bash
pki certificate [options]
```

| Option                 | Description                          | Default                            |
| ---------------------- | ------------------------------------ | ---------------------------------- |
| `-a, --applicationUri` | Application URI                      | `urn:{hostname}:Node-OPCUA-Server` |
| `-o, --output`         | Output certificate filename          | `my_certificate.pem`               |
| `--selfSigned`         | Create self-signed certificate       | `false`                            |
| `-v, --validity`       | Validity in days                     | `365`                              |
| `--dns`                | Valid domain names (comma separated) | `{hostname}`                       |
| `--ip`                 | Valid IPs (comma separated)          |                                    |
| `--subject`            | Certificate subject                  |                                    |
| `-r, --root`           | Certificate folder location          | `{CWD}/certificates`               |
| `-c, --CAFolder`       | CA folder location                   | `{root}/CA`                        |
| `--PKIFolder`          | PKI folder location                  | `{root}/PKI`                       |
| `-p, --privateKey`     | Private key to use                   | `{PKIFolder}/own/private_key.pem`  |

**Example — self-signed certificate with SANs:**

```bash
pki certificate \
  --selfSigned \
  --dns=machine1.com,machine2.com \
  --ip="192.1.2.3;192.3.4.5" \
  -a "urn:{hostname}:My-OPCUA-Server" \
  -o my_self_signed_certificate.pem
```

---

### csr

Create a certificate signing request.

```bash
pki csr [options]
```

| Option                 | Description                          | Default                              |
| ---------------------- | ------------------------------------ | ------------------------------------ |
| `-a, --applicationUri` | Application URI                      | `urn:{hostname}:Node-OPCUA-Server`   |
| `-o, --output`         | Output CSR filename                  | `my_certificate_signing_request.csr` |
| `--dns`                | Valid domain names (comma separated) | `{hostname}`                         |
| `--ip`                 | Valid IPs (comma separated)          |                                      |
| `--subject`            | Certificate subject                  | `/CN=Certificate`                    |

---

### sign

Sign a CSR and generate a certificate (requires a CA).

```bash
pki sign [options]
```

| Option           | Description                 | Default                              |
| ---------------- | --------------------------- | ------------------------------------ |
| `-i, --csr`      | CSR file to sign            | `my_certificate_signing_request.csr` |
| `-o, --output`   | Output certificate filename | `my_certificate.pem`                 |
| `-v, --validity` | Validity in days            | `365`                                |
| `-r, --root`     | Certificate folder location | `{CWD}/certificates`                 |
| `-c, --CAFolder` | CA folder location          | `{root}/CA`                          |

---

### demo

Create a set of demo certificates for testing.

```bash
pki demo [--dev] [--silent] [--clean]
```

| Option    | Description                                               |
| --------- | --------------------------------------------------------- |
| `--dev`   | Create additional certificates for dev testing            |
| `--clean` | Purge existing certificate directory (**use with care!**) |

---

## Programmatic Usage

```typescript
import { CertificateManager } from "node-opcua-pki";

const certManager = new CertificateManager({
    rootFolder: "./my_pki",
    keySize: 2048,
    name: "PKI",
});

await certManager.initialize();

// Create a self-signed certificate
await certManager.createSelfSignedCertificate({
    applicationUri: "urn:my-server:application",
    subject: "/CN=My Server/O=My Organization",
    dns: ["localhost"],
    ip: ["127.0.0.1"],
    validity: 365,
    outputFile: "my_certificate.pem",
});
```

## References

- [OPC Foundation GDS File Store](https://reference.opcfoundation.org/GDS/docs/F.1/)
- [RFC 5280 — X.509 PKI Certificate and CRL Profile](https://tools.ietf.org/html/rfc5280)
- [Certification Path Validation](https://en.wikipedia.org/wiki/Certification_path_validation_algorithm)

## Support

NodeOPCUA PKI is developed and maintained by [sterfive.com](https://www.sterfive.com).

[![Professional Support](https://img.shields.io/static/v1?style=for-the-badge&label=Professional&message=Support&labelColor=blue&color=green&logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2ZXJzaW9uPSIxLjEiIGlkPSJMYXllcl8xIiB4PSIwcHgiIHk9IjBweCIgdmlld0JveD0iMCAwIDQ5MS41MiA0OTEuNTIiIHN0eWxlPSJlbmFibGUtYmFja2dyb3VuZDpuZXcgMCAwIDQ5MS41MiA0OTEuNTI7IiB4bWw6c3BhY2U9InByZXNlcnZlIj4NCjxnPg0KCTxnPg0KCQk8cGF0aCBkPSJNNDg3Ljk4OSwzODkuNzU1bC05My4xMDktOTIuOTc2Yy00LjgxMy00LjgwNi0xMi42NDItNC42NzQtMTcuMjczLDAuMzA3Yy03LjE0OCw3LjY4OS0xNC42NCwxNS41NTQtMjEuNzMsMjIuNjM0ICAgIGMtMC4yNzEsMC4yNy0wLjUwMSwwLjQ5My0wLjc2MywwLjc1NUw0NjcuMyw0MzIuNTA0YzguOTEtMTAuNjE0LDE2LjY1Ny0yMC40MSwyMS43My0yNi45NyAgICBDNDkyLjcyLDQwMC43NjIsNDkyLjI1NywzOTQuMDE5LDQ4Ny45ODksMzg5Ljc1NXoiLz4NCgk8L2c+DQo8L2c+DQo8Zz4NCgk8Zz4NCgkJPHBhdGggZD0iTTMzNC4zLDMzNy42NjFjLTM0LjMwNCwxMS4zNzktNzcuNTYsMC40MTMtMTE0LjU1NC0yOS41NDJjLTQ5LjAyMS0zOS42OTMtNzUuOTcyLTEwMi42NDItNjUuODM4LTE1MC41OTNMMzcuNjM0LDQxLjQxOCAgICBDMTcuNjUzLDU5LjQyNCwwLDc4LjU0NSwwLDkwYzAsMTQxLjc1MSwyNjAuMzQ0LDQxNS44OTYsNDAxLjUwMyw0MDAuOTMxYzExLjI5Ni0xLjE5OCwzMC4xNzYtMTguNjUxLDQ4LjA2Mi0zOC4xNjdMMzM0LjMsMzM3LjY2MSAgICB6Ii8+DQoJPC9nPg0KPC9nPg0KPGc+DQoJPGc+DQoJCTxwYXRoIGQ9Ik0xOTMuODU0LDk2LjA0MUwxMDEuMjEzLDMuNTNjLTQuMjI1LTQuMjItMTAuODgyLTQuNzI0LTE1LjY2NC0xLjE0NWMtNi42NTQsNC45ODMtMTYuNjQ4LDEyLjY1MS0yNy40NTMsMjEuNDk4ICAgIGwxMTEuOTQ1LDExMS43ODVjMC4wNjEtMC4wNiwwLjExMS0wLjExMywwLjE3Mi0wLjE3NGM3LjIzOC03LjIyOCwxNS4zNTUtMTQuODg1LDIzLjI5MS0yMi4xNjcgICAgQzE5OC41MzQsMTA4LjcxMywxOTguNjg0LDEwMC44NjMsMTkzLjg1NCw5Ni4wNDF6Ii8+DQoJPC9nPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPC9zdmc+)](https://support.sterfive.com)

## License

MIT — Copyright (c) 2014-2026 Etienne Rossignon / [Sterfive](https://www.sterfive.com)

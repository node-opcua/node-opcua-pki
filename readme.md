# node-opcua-pki

[![NPM download](https://img.shields.io/npm/dm/node-opcua-pki.svg)](https://www.npmtrends.com/node-opcua-pki)
[![NPM version](https://img.shields.io/npm/v/node-opcua-pki)](https://www.npmjs.com/package/node-opcua-pki?activeTab=versions)
[![Build Status](https://github.com/node-opcua/node-opcua-pki/actions/workflows/ci.yml/badge.svg)](https://github.com/node-opcua/node-opcua-pki/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/node-opcua/node-opcua-pki/badge.svg?branch=master)](https://coveralls.io/github/node-opcua/node-opcua-pki?branch=master)
[![FOSSA Status](https://app.fossa.com/api/projects/custom%2B20248%2Fgithub.com%2Fnode-opcua%2Fnode-opcua-pki.svg?type=shield)](https://app.fossa.com/projects/custom%2B20248%2Fgithub.com%2Fnode-opcua%2Fnode-opcua-pki?ref=badge_shield)

**Production-grade PKI management for [OPC UA](https://node-opcua.github.io/)** — secure your industrial devices with proper certificates in minutes, not days.

## Why node-opcua-pki?

- 🔒 **OPC UA compliant** — PKI directory structure per Part 6 §6.2.6, out of the box
- 🏗️ **Full CA lifecycle** — create, sign, revoke, renew certificates and CRLs
- 🖥️ **Cross-platform** — Windows, Linux, macOS, Alpine, with automatic OpenSSL detection
- 🧩 **CLI + API** — use from the command line or embed in your Node.js application
- 🛡️ **Battle-tested** — 12 years of continuous development, powering production OPC UA deployments worldwide

## Quick Start

```bash
# Create a full PKI with demo certificates — no install needed
npx node-opcua-pki demo

# Create a self-signed certificate
npx node-opcua-pki certificate --selfSigned -o my_cert.pem

# Set up a Certificate Authority
npx node-opcua-pki createCA
npx node-opcua-pki createPKI
```

📖 **Full CLI & API reference**: [packages/node-opcua-pki/readme.md](packages/node-opcua-pki/readme.md)

🔐 **Keeping the CA key in an HSM or KMS**: [hsm-kms-signing.md](hsm-kms-signing.md). The CA
can sign through a hardware module or cloud KMS, so no private key is ever written to disk.

## 🏢 Professional Support

node-opcua-pki is developed and maintained by [Sterfive](https://www.sterfive.com), the company behind the [node-opcua](https://github.com/node-opcua/node-opcua) ecosystem.

|  | Community | Professional |
|---|:---:|:---:|
| Full documentation & CLI | ✅ | ✅ |
| Bug fixes & security patches | Best effort | **Priority SLA** |
| Security advisories | Public | **Early access** |
| Custom certificate workflows | — | ✅ |
| Dedicated consulting | — | ✅ |
| PKI architecture review | — | ✅ |

[![Professional Support](https://img.shields.io/static/v1?style=for-the-badge&label=Professional&message=Support&labelColor=blue&color=green&logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2ZXJzaW9uPSIxLjEiIGlkPSJMYXllcl8xIiB4PSIwcHgiIHk9IjBweCIgdmlld0JveD0iMCAwIDQ5MS41MiA0OTEuNTIiIHN0eWxlPSJlbmFibGUtYmFja2dyb3VuZDpuZXcgMCAwIDQ5MS41MiA0OTEuNTI7IiB4bWw6c3BhY2U9InByZXNlcnZlIj4NCjxnPg0KCTxnPg0KCQk8cGF0aCBkPSJNNDg3Ljk4OSwzODkuNzU1bC05My4xMDktOTIuOTc2Yy00LjgxMy00LjgwNi0xMi42NDItNC42NzQtMTcuMjczLDAuMzA3Yy03LjE0OCw3LjY4OS0xNC42NCwxNS41NTQtMjEuNzMsMjIuNjM0ICAgIGMtMC4yNzEsMC4yNy0wLjUwMSwwLjQ5My0wLjc2MywwLjc1NUw0NjcuMyw0MzIuNTA0YzguOTEtMTAuNjE0LDE2LjY1Ny0yMC40MSwyMS43My0yNi45NyAgICBDNDkyLjcyLDQwMC43NjIsNDkyLjI1NywzOTQuMDE5LDQ4Ny45ODksMzg5Ljc1NXoiLz4NCgk8L2c+DQo8L2c+DQo8Zz4NCgk8Zz4NCgkJPHBhdGggZD0iTTMzNC4zLDMzNy42NjFjLTM0LjMwNCwxMS4zNzktNzcuNTYsMC40MTMtMTE0LjU1NC0yOS41NDJjLTQ5LjAyMS0zOS42OTMtNzUuOTcyLTEwMi42NDItNjUuODM4LTE1MC41OTNMMzcuNjM0LDQxLjQxOCAgICBDMTcuNjUzLDU5LjQyNCwwLDc4LjU0NSwwLDkwYzAsMTQxLjc1MSwyNjAuMzQ0LDQxNS44OTYsNDAxLjUwMyw0MDAuOTMxYzExLjI5Ni0xLjE5OCwzMC4xNzYtMTguNjUxLDQ4LjA2Mi0zOC4xNjdMMzM0LjMsMzM3LjY2MSAgICB6Ii8+DQoJPC9nPg0KPC9nPg0KPGc+DQoJPGc+DQoJCTxwYXRoIGQ9Ik0xOTMuODU0LDk2LjA0MUwxMDEuMjEzLDMuNTNjLTQuMjI1LTQuMjItMTAuODgyLTQuNzI0LTE1LjY2NC0xLjE0NWMtNi42NTQsNC45ODMtMTYuNjQ4LDEyLjY1MS0yNy40NTMsMjEuNDk4ICAgIGwxMTEuOTQ1LDExMS43ODVjMC4wNjEtMC4wNiwwLjExMS0wLjExMywwLjE3Mi0wLjE3NGM3LjIzOC03LjIyOCwxNS4zNTUtMTQuODg1LDIzLjI5MS0yMi4xNjcgICAgQzE5OC41MzQsMTA4LjcxMywxOTguNjg0LDEwMC44NjMsMTkzLjg1NCw5Ni4wNDF6Ii8+DQoJPC9nPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPC9zdmc+)](https://support.sterfive.com)

Or [contact Sterfive](mailto:contact@sterfive.com) for dedicated consulting and enterprise needs.

## :heart: Sponsors & Backers

If you rely on node-opcua-pki in production, please consider [sponsoring us](https://github.com/sponsors/node-opcua) to help maintain this project.

If your company would like to participate and influence the development of future versions, [get in touch](mailto:contact@sterfive.com).

## Contributing

See [developer.md](developer.md) for build instructions, project structure, and release process.

## References

- [OPC Foundation GDS File Store](https://reference.opcfoundation.org/GDS/docs/F.1/)
- [RFC 5280 — X.509 PKI Certificate and CRL Profile](https://tools.ietf.org/html/rfc5280)

## License

MIT — Copyright (c) 2014-2026 Etienne Rossignon / [Sterfive](https://www.sterfive.com)

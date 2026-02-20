# node-opcua-pki

[![NPM download](https://img.shields.io/npm/dm/node-opcua-pki.svg)](https://www.npmtrends.com/node-opcua-pki)
[![NPM version](https://img.shields.io/npm/v/node-opcua-pki)](https://www.npmjs.com/package/node-opcua-pki?activeTab=versions)
[![Build Status](https://github.com/node-opcua/node-opcua-pki/actions/workflows/ci.yml/badge.svg)](https://github.com/node-opcua/node-opcua-pki/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/node-opcua/node-opcua-pki/badge.svg?branch=master)](https://coveralls.io/github/node-opcua/node-opcua-pki?branch=master)
[![FOSSA Status](https://app.fossa.com/api/projects/custom%2B20248%2Fgithub.com%2Fnode-opcua%2Fnode-opcua-pki.svg?type=shield)](https://app.fossa.com/projects/custom%2B20248%2Fgithub.com%2Fnode-opcua%2Fnode-opcua-pki?ref=badge_shield)

**PKI management for [node-opcua](https://node-opcua.github.io/)** — create and manage OPC UA certificates, Certificate Authorities, and Public Key Infrastructures from the command line or programmatically.

📦 **Published package**: [node-opcua-pki on npm](https://www.npmjs.com/package/node-opcua-pki)
📖 **CLI & API documentation**: [packages/node-opcua-pki/readme.md](packages/node-opcua-pki/readme.md)

## Repository Structure

This repository is organized as a mini monorepo:

```
node-opcua-pki/
├── packages/
│   └── node-opcua-pki/       ← published to npm
│       ├── lib/              source code
│       ├── bin/              CLI entry points
│       └── dist/             build output
├── test/                     test suite
├── tsup.config.ts            build configuration
├── tsconfig.json             TypeScript configuration
└── biome.json                linter & formatter configuration
```

## Development

### Prerequisites

- **Node.js** ≥ 18
- **OpenSSL** or **LibreSSL** (auto-installed on Windows)

### Getting Started

```bash
git clone https://github.com/node-opcua/node-opcua-pki.git
cd node-opcua-pki
npm install
npm run build
```

### Scripts

| Script             | Description                                   |
| ------------------ | --------------------------------------------- |
| `npm run build`    | Build the package with tsup (ESM + CJS + DTS) |
| `npm test`         | Run the test suite with mocha                 |
| `npm run test:cjs` | Verify CommonJS imports work                  |
| `npm run test:esm` | Verify ESM imports work                       |
| `npm run lint`     | Run biome linter                              |
| `npm run format`   | Format code with biome                        |

### Pre-commit Hooks

This project uses [Husky](https://typicode.github.io/husky/) to enforce code quality. On every commit:

1. `biome format --write --staged` — auto-formats staged files
2. `biome check --staged` — lints and blocks commit on errors

## Support

Sterfive provides this module free of charge, "as is," with the hope that it will be useful to you. However, any support requests, bug fixes, or enhancements are handled exclusively through our paid services.

We highly recommend subscribing to our [support program](https://support.sterfive.com) to ensure your requests are addressed and resolved.

## Getting Professional Support

NodeOPCUA PKI is developed and maintained by [sterfive.com](https://www.sterfive.com).

To get professional support, consider subscribing to the node-opcua membership community:

[![Professional Support](https://img.shields.io/static/v1?style=for-the-badge&label=Professional&message=Support&labelColor=blue&color=green&logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2ZXJzaW9uPSIxLjEiIGlkPSJMYXllcl8xIiB4PSIwcHgiIHk9IjBweCIgdmlld0JveD0iMCAwIDQ5MS41MiA0OTEuNTIiIHN0eWxlPSJlbmFibGUtYmFja2dyb3VuZDpuZXcgMCAwIDQ5MS41MiA0OTEuNTI7IiB4bWw6c3BhY2U9InByZXNlcnZlIj4NCjxnPg0KCTxnPg0KCQk8cGF0aCBkPSJNNDg3Ljk4OSwzODkuNzU1bC05My4xMDktOTIuOTc2Yy00LjgxMy00LjgwNi0xMi42NDItNC42NzQtMTcuMjczLDAuMzA3Yy03LjE0OCw3LjY4OS0xNC42NCwxNS41NTQtMjEuNzMsMjIuNjM0ICAgIGMtMC4yNzEsMC4yNy0wLjUwMSwwLjQ5My0wLjc2MywwLjc1NUw0NjcuMyw0MzIuNTA0YzguOTEtMTAuNjE0LDE2LjY1Ny0yMC40MSwyMS43My0yNi45NyAgICBDNDkyLjcyLDQwMC43NjIsNDkyLjI1NywzOTQuMDE5LDQ4Ny45ODksMzg5Ljc1NXoiLz4NCgk8L2c+DQo8L2c+DQo8Zz4NCgk8Zz4NCgkJPHBhdGggZD0iTTMzNC4zLDMzNy42NjFjLTM0LjMwNCwxMS4zNzktNzcuNTYsMC40MTMtMTE0LjU1NC0yOS41NDJjLTQ5LjAyMS0zOS42OTMtNzUuOTcyLTEwMi42NDItNjUuODM4LTE1MC41OTNMMzcuNjM0LDQxLjQxOCAgICBDMTcuNjUzLDU5LjQyNCwwLDc4LjU0NSwwLDkwYzAsMTQxLjc1MSwyNjAuMzQ0LDQxNS44OTYsNDAxLjUwMyw0MDAuOTMxYzExLjI5Ni0xLjE5OCwzMC4xNzYtMTguNjUxLDQ4LjA2Mi0zOC4xNjdMMzM0LjMsMzM3LjY2MSAgICB6Ii8+DQoJPC9nPg0KPC9nPg0KPGc+DQoJPGc+DQoJCTxwYXRoIGQ9Ik0xOTMuODU0LDk2LjA0MUwxMDEuMjEzLDMuNTNjLTQuMjI1LTQuMjItMTAuODgyLTQuNzI0LTE1LjY2NC0xLjE0NWMtNi42NTQsNC45ODMtMTYuNjQ4LDEyLjY1MS0yNy40NTMsMjEuNDk4ICAgIGwxMTEuOTQ1LDExMS43ODVjMC4wNjEtMC4wNiwwLjExMS0wLjExMywwLjE3Mi0wLjE3NGM3LjIzOC03LjIyOCwxNS4zNTUtMTQuODg1LDIzLjI5MS0yMi4xNjcgICAgQzE5OC41MzQsMTA4LjcxMywxOTguNjg0LDEwMC44NjMsMTkzLjg1NCw5Ni4wNDF6Ii8+DQoJPC9nPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPC9zdmc+)](https://support.sterfive.com)

or contact [sterfive](https://www.sterfive.com) for dedicated consulting and more advanced support.

## :heart: Supporting the Development Effort — Sponsors & Backers

If you like node-opcua-pki and if you are relying on it in one of your projects, please consider becoming a backer and [sponsoring us](https://github.com/sponsors/node-opcua), this will help us to maintain a high-quality stack and constant evolution of this module.

If your company would like to participate and influence the development of future versions of node-opcua please contact [sterfive](mailto:contact@sterfive.com).

## License

MIT — Copyright (c) 2014-2026 Etienne Rossignon / [Sterfive](https://www.sterfive.com)

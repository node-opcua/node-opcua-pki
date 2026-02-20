# Developer Guide

## Project Structure

This is a mini monorepo using npm workspaces:

```
node-opcua-pki/
├── packages/
│   └── node-opcua-pki/     # publishable npm package
│       ├── lib/             # source code
│       ├── bin/             # CLI entry points
│       ├── dist/            # built output (tsup)
│       └── package.json     # published package.json
├── test/                    # tests (run from root)
├── tsup.config.ts           # build config
├── tsconfig.json            # TypeScript config with path aliases
├── lerna.json               # lerna versioning config
└── package.json             # root monorepo package (private)
```

## Build

```bash
npm run build
```

## Test

```bash
npm run test           # mocha tests
npm run test:cjs       # CJS import smoke test
npm run test:esm       # ESM import smoke test
npm run test:all       # all of the above
```

## Lint & Format

```bash
npm run lint           # biome lint
npm run format         # biome format --write
```

## Release & Publish

The release process is split into two steps:

### Step 1 — Version bump & tag (local)

Use `lerna version` to bump the version in
`packages/node-opcua-pki/package.json`, commit, tag, and push:

```bash
npm run release            # interactive version prompt
npm run release:minor      # minor bump
npm run release:major      # major bump
```

This will:

1. Bump the version in `packages/node-opcua-pki/package.json`
2. Generate/update `CHANGELOG.md` from conventional commits
3. Commit with message `chore: release vX.Y.Z`
4. Create a git tag `vX.Y.Z`
5. Push the commit and tag to origin

> **Note:** lerna does NOT publish to npm here.
> Publishing is handled by GitHub Actions.

### Step 2 — Publish to npm (GitHub Actions)

The [publish workflow](.github/workflows/publish.yml) is
triggered automatically when a `v*` tag is pushed. It can also
be triggered manually via **workflow_dispatch** with a choice
of dist-tag (`latest`, `next`, `rc`, `beta`, `alpha`).

The workflow:

1. Checks out the tagged commit
2. Installs dependencies and builds
3. Runs `npm publish -w packages/node-opcua-pki --tag <dist-tag>`
4. Creates a GitHub Release with auto-generated notes

### Quick Reference

```bash
# Full release flow:
npm run release:minor      # bump, commit, tag, push
                           # → GitHub Actions publishes to npm
```

# Private Key Protection

How `node-opcua-pki` protects the private keys it generates and stores, what
that protection does and does not cover, and how to opt in to
passphrase-encrypted keys on a `CertificateManager`.

## Table of Contents

- [What is protected by default](#what-is-protected-by-default)
- [Passphrase-encrypted keys (opt-in)](#passphrase-encrypted-keys-opt-in)
- [Key provider (HSM / KMS)](#key-provider-hsm--kms)
- [Enabling, rotating, or removing a passphrase on an existing install](#enabling-rotating-or-removing-a-passphrase-on-an-existing-install)
- [Compatibility: who else reads the key file](#compatibility-who-else-reads-the-key-file)
- [How passphrases reach openssl](#how-passphrases-reach-openssl)
- [Threat model: what this does not protect against](#threat-model-what-this-does-not-protect-against)

---

## What is protected by default

`CertificateManager` and `CertificateAuthority` store private keys on the local
filesystem: `own/private/private_key.pem` and `private/cakey.pem`.

On POSIX systems, `own/private` and `private/` are created with owner-only
permissions (`0700` on the directory, `0600` on the key file), and those
permissions are repaired on every `initialize()`. This protects against a
local, unprivileged user or process that can read the key's parent directory.

On Windows this is a no-op: `chmod` and directory modes only toggle the
read-only attribute and cannot express owner-only access. Restricting key
material with Windows ACLs is tracked as future work.

By default the key file itself is **plaintext PKCS#8**. That is unchanged from
earlier releases so that existing consumers of the file keep working (see
[Compatibility](#compatibility-who-else-reads-the-key-file)).

---

## Passphrase-encrypted keys (opt-in)

`CertificateManager` accepts a `privateKeyPassphrase` option:

```typescript
import { CertificateManager } from "node-opcua-pki";

const cm = new CertificateManager({
    location: "./my_pki",
    // a literal, or a function resolved lazily (preferred: read it from a secret store)
    privateKeyPassphrase: async () => secrets.get("pki/private-key-passphrase"),
});
await cm.initialize();
```

Behaviour once the option is set:

- A freshly generated key is written as passphrase-encrypted PKCS#8
  (`-----BEGIN ENCRYPTED PRIVATE KEY-----`, AES-256-CBC).
- An **existing plaintext key is encrypted in place** the first time
  `initialize()` runs with the passphrase (atomic temp file + rename, same as
  `reencryptPrivateKey()`), so turning the option on never leaves the key in
  cleartext.
- An existing encrypted key must match the passphrase. A missing or wrong
  passphrase makes `initialize()` **fail closed** with
  `PrivateKeyPassphraseRequiredError` (re-exported from `node-opcua-pki`).
  There is no plaintext fallback.
- A failed `initialize()` leaves the instance re-initializable: fix the
  passphrase and call `initialize()` again.
- The decrypted key is read once and cached for the lifetime of the instance,
  so a passphrase function is called at most once per instance (concurrent
  first calls share one resolution; a failed read is not cached). The cache is
  dropped on `dispose()` and after `reencryptPrivateKey()`.
- The passphrase is never logged, never placed on an openssl command line,
  and never written to disk.

`getPrivateKey()` returns the in-memory `PrivateKey` (from disk, decrypted, or
from the provider below). `createSelfSignedCertificate()` and
`createCertificateRequest()` use it directly and never re-read the file.

`CertificateAuthority` does **not** support `privateKeyPassphrase` or
`privateKeyProvider` yet: its signing, revocation and CRL paths call openssl
with `private/cakey.pem` from the CA's own configuration, so encrypting that key
would require threading `-passin` through every one of those calls. That is a
separate change; today `private/cakey.pem` is always plaintext.

---

## Key provider (HSM / KMS)

To keep the key out of the filesystem altogether, supply a
`privateKeyProvider`:

```typescript
import type { PrivateKey } from "node-opcua-crypto";

const cm = new CertificateManager({
    location: "./my_pki",
    privateKeyProvider: {
        async getPrivateKey(): Promise<PrivateKey> {
            return await myKms.loadOpcUaKey();
        },
    },
});
```

With a provider configured, `own/private/private_key.pem` is neither
generated nor read, `privateKeyPassphrase` is ignored, and the provider is
consulted on every `getPrivateKey()` call (it is the authority on the current
key; nothing is cached). `reencryptPrivateKey()` throws, since there is no file
to rewrite.

---

## Enabling, rotating, or removing a passphrase on an existing install

```typescript
// enable (key is currently plaintext)
await cm.reencryptPrivateKey(undefined, "new passphrase");

// rotate
await cm.reencryptPrivateKey("old passphrase", "new passphrase");

// remove (back to plaintext)
await cm.reencryptPrivateKey("old passphrase", undefined);
```

`reencryptPrivateKey()` runs under the same lock as `initialize()`, writes to a
temporary file next to the key, renames it into place atomically, and removes
the temporary file if anything fails, so a rotation to plaintext can never
leave a stray cleartext copy behind. It only rewrites the file: construct a new
`CertificateManager` with the new passphrase to continue using it.

Simply constructing a `CertificateManager` with `privateKeyPassphrase` on an
install whose key is still plaintext has the same effect as the "enable" call
above, performed by `initialize()`.

---

## Compatibility: who else reads the key file

Once the key is encrypted, **every** reader of `own/private/private_key.pem`
must be given the passphrase, or it will fail (by design, not silently):

| Reader | What to do |
| --- | --- |
| Your own code | call `cm.getPrivateKey()` instead of reading the file |
| `createPFX()` | pass `privateKeyPassphrase` in `CreatePFXOptions` |
| `getPublicKeyFromPrivateKey()` | pass the passphrase as the third argument |
| External `openssl` tooling | add `-passin` (prefer `env:` or `file:` over `pass:`) |
| Consumers that read the file directly, e.g. node-opcua's `OPCUAServer` | they still expect plaintext; do not enable the passphrase on a `CertificateManager` shared with such a consumer unless it has been updated to go through `getPrivateKey()` |

---

## How passphrases reach openssl

Some operations invoke the `openssl` binary (PFX/PKCS#12 handling, CA operations).
Where a passphrase is involved (`createPFX`, `extract*FromPFX`,
`convertPFXtoPEM`, `dumpPFX`, `getPublicKeyFromPrivateKey`):

- `openssl` is spawned directly, without a shell: every argument (file paths,
  subjects, options) reaches it as one argv entry, so no value can be
  reinterpreted as a shell metacharacter, a redirection, or a second command;
- a passphrase is passed through a per-invocation environment variable using
  openssl's `-passin env:NAME` / `-passout env:NAME` forms, never in argv, so
  it does not appear in the process list;
- debug output redacts per-invocation environment values (only variable names
  are printed);
- `-passin` is always sent when a private key is read (empty for a plaintext
  key), so an encrypted key without a passphrase fails fast with `bad decrypt`
  instead of leaving openssl waiting on a terminal prompt;
- the child gets a curated allowlist of the parent process environment (shell
  and loader essentials, locale, `OPENSSL_*`, `LD_LIBRARY_PATH` / `DYLD_*`),
  not the whole of it, so unrelated secrets in the host application's
  environment are not exposed to the openssl process; the same environment is
  used to discover the openssl binary and to run it;
- the child's stdin is `/dev/null`, so openssl can never block reading a
  password interactively.

---

## Threat model: what this does not protect against

- A user or process with root/Administrator privileges on the same host.
- Memory scraping while the process holds a decrypted key.
- Windows filesystem access: see [What is protected by default](#what-is-protected-by-default).
- Passphrase visibility via the process environment table (for example
  `/proc/<pid>/environ` on Linux) to another process running as the **same
  user** while an openssl child is in flight. Passing the passphrase via the
  environment removes it from `argv` and from the shell, but does not hide it
  from a same-user process with the right access.
- Characters that openssl's own configuration-file syntax interprets
  (`$`, backticks, quotes) inside a `CertificateAuthority` `location`: the CA
  embeds its directory in the generated `caconfig.cnf`, and openssl's config
  parser, not a shell, expands or strips them there. `CertificateManager`
  locations and all subjects and file paths are unaffected. Do not build a CA
  location from untrusted input.
- Wherever you choose to store the passphrase. This library protects the key
  on disk, not your passphrase management. Prefer the function form of
  `privateKeyPassphrase`, sourced from a real secret store, over a literal in
  a configuration file.

Security vulnerabilities should be reported privately as described in
[SECURITY.md](../../../SECURITY.md).

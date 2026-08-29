# Private Key Protection

How `node-opcua-pki` protects the private keys it generates and stores, what
that protection does and does not cover, and how to opt in to
passphrase-encrypted keys on a `CertificateManager`.

## Table of Contents

- [What is protected by default](#what-is-protected-by-default)
- [Passphrase-encrypted keys (opt-in)](#passphrase-encrypted-keys-opt-in)
- [Key provider (HSM / KMS)](#key-provider-hsm--kms)
- [Opaque keys: `keyOperations` (HSM / KMS, key never enters the process)](#opaque-keys-keyoperations-hsm--kms-key-never-enters-the-process)
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

`CertificateAuthority` accepts the same `privateKeyPassphrase` option for
`private/cakey.pem`, with the same behaviour: a fresh CA key is written
encrypted, an existing plaintext CA key is encrypted in place by
`initialize()` / `initializeCSR()`, and a missing or wrong passphrase fails
`initialize()` closed. Every `openssl` invocation that loads the CA key (CSR,
self-sign, signing a subordinate CA or an end-entity CSR, revocation, CRL
generation) receives it through `-passin env:`, so nothing changes in how you
call the CA. `getPrivateKey()` and `reencryptPrivateKey()` exist on the CA
too. Two CA-specific notes:

- A subordinate CA (`issuerCA` set) is signed with the **issuer's** key, so
  the issuer's own `privateKeyPassphrase` is used for that step; each CA
  object carries the passphrase for its own key only.
- The CA hands the passphrase to each openssl child, so it keeps the
  *resolved passphrase* (not just the decrypted key) in memory for the
  instance's lifetime; a passphrase function is still called at most once
  per instance.

`privateKeyProvider` is **not** available on `CertificateAuthority`: its
signing and CRL paths are `openssl ca` / `openssl x509` reading a key *file*,
so an HSM/KMS-sourced key cannot be used without writing it to disk. Doing
that properly means a native (non-openssl) CA backend, which is a separate
project.

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

Note that a `privateKeyProvider` still **hands the key material back** to the
process: it changes where the key is stored, not who can read it. If the key
does not need to be exportable, prefer the opaque
[`keyOperations`](#opaque-keys-keyoperations-hsm--kms-key-never-enters-the-process)
option below.

---

## Opaque keys: `keyOperations` (HSM / KMS, key never enters the process)

`keyOperations` goes one step further than `privateKeyProvider`: the manager
gets an object it can *use* — sign, decrypt — but through which the key can
never be read. The key stays inside the HSM, KMS, TPM or OS keystore,
non-exportable, and every use of it is visible in that system's audit log.

|  | `privateKeyPassphrase` | `privateKeyProvider` | `keyOperations` |
| --- | --- | --- | --- |
| Key at rest | encrypted file on disk | wherever the provider reads it from | inside the HSM/KMS |
| Key in process memory | yes (decrypted once) | yes (returned by the provider) | **never** |
| `getPrivateKey()` | returns the key | returns the key | throws `PrivateKeyUnavailableError` |
| Certificate renewal (CSR) | yes | yes | yes, signed inside the HSM |
| Use when | the key may live on disk, encrypted | the key is stored elsewhere but may be exported | the key must be non-exportable |

A provider implements `IKeyOperations` (re-exported from `node-opcua-pki`,
defined in `node-opcua-crypto`). The minimal, KMS-style shape:

```typescript
import type { AsymmetricDecryptParams, AsymmetricSignParams, IKeyOperations, KeyMetadata } from "node-opcua-pki";

class MyKmsKeyOperations implements IKeyOperations {
    async sign(data: Uint8Array, params: AsymmetricSignParams): Promise<Buffer> {
        // params.padding: "RSA-PKCS1-v1_5" | "RSA-PSS" (salt length = digest length)
        // params.hash:    "SHA-1" | "SHA-256"
        return Buffer.from(await myKms.sign({ keyName: "opcua-app-key", data, algorithm: toKmsSignAlgorithm(params) }));
    }
    async decryptBlock(block: Uint8Array, params: AsymmetricDecryptParams): Promise<Buffer> {
        // exactly ONE RSA block per call (block.length === modulusLength)
        return Buffer.from(await myKms.decrypt({ keyName: "opcua-app-key", ciphertext: block, algorithm: toKmsDecryptAlgorithm(params) }));
    }
    async getKeyMetadata(): Promise<KeyMetadata> {
        // declared, not inspected: an HSM-held key exposes nothing to introspect
        return { keyType: "RSA", modulusLength: 256 }; // bytes: a 2048-bit key
    }
    async getPublicKey(): Promise<ArrayBuffer> {
        return await myKms.getPublicKey("opcua-app-key"); // SPKI DER
    }
}
```

`getPublicKey` is formally optional on the interface, but certificate
operations need it (a CSR embeds the public key, a self-signed certificate
carries it), and with an opaque key there is nowhere else it can come from —
omit it and those operations fail with an error naming it.

Behaviour once the option is set:

- `own/private/private_key.pem` is neither generated nor read.
- `initialize()` **fails closed** if the provider cannot answer
  `getKeyMetadata()` (unreachable HSM, misconfiguration).
- `getPrivateKey()` and `reencryptPrivateKey()` throw
  `PrivateKeyUnavailableError` (re-exported from `node-opcua-pki`): there is
  no key material to return or rewrite. Use `getKeyOperations()` instead;
  `isPrivateKeyOpaque()` tells the two configurations apart.
- Mutually exclusive with `privateKeyProvider` and `privateKeyPassphrase`,
  which both describe key *material*.

The certificate lifecycle works with the key staying put — including the
renewal workflow (new certificate, same HSM key):

```typescript
import { CertificateManager } from "node-opcua-pki";

const cm = new CertificateManager({ location: "./my_pki", keyOperations: new MyKmsKeyOperations() });
await cm.initialize();

// bootstrap: a self-signed certificate over the HSM-held key
await cm.createSelfSignedCertificate({
    applicationUri: "urn:myhost:myapp",
    subject: "CN=MyApp",
    dns: ["myhost"],
    startDate: new Date(),
    validity: 365,
});

// renewal: a CSR over the SAME key, to be signed by your CA —
// the proof-of-possession signature is produced inside the HSM
const csrFile = await cm.createCertificateRequest({
    applicationUri: "urn:myhost:myapp",
    subject: "CN=MyApp",
    dns: ["myhost"],
});
```

Only the openssl-free code paths support an opaque key (openssl reads a key
*file*); `CertificateManager` uses those paths for both operations above.

For the **CA-side** equivalent — keeping the CA's own signing key in an
HSM/KMS via a `CaSigner` — see
[hsm-kms-signing.md](../../../hsm-kms-signing.md). One HSM integration can
serve both: `caSignerFromKeyOperations` (from `node-opcua-crypto`) adapts an
`IKeyOperations` to the `CaSigner` interface.

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
- Wherever you choose to store the passphrase. This library protects the key
  on disk, not your passphrase management. Prefer the function form of
  `privateKeyPassphrase`, sourced from a real secret store, over a literal in
  a configuration file.
- Even with an opaque `keyOperations` key, an attacker with code execution
  inside the process can still *use* the key through the provider while
  resident. What the opaque configuration guarantees is that the key cannot
  be exfiltrated — memory dumps, disk or backup theft reveal nothing — and
  that every use is visible in the HSM/KMS audit log. The accurate claim is
  "non-exportable, auditable identity key", not "keys never used by a
  compromised process".

Security vulnerabilities should be reported privately as described in
[SECURITY.md](../../../SECURITY.md).

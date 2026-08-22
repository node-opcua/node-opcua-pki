# Keeping the CA key in an HSM or KMS

By default a `CertificateAuthority` generates `private/cakey.pem` and signs with it.
That file is the whole security of the CA: anyone who reads it can issue certificates
your fleet trusts, forever, and there is no way to tell afterwards that they did.

A `CaSigner` removes the file. The key stays inside a hardware module or a cloud KMS,
and the CA asks it to sign. Nothing in `node-opcua-pki` ever holds the private key,
because there is nothing to hold.

## The interface

A signer exposes exactly what an HSM offers, and nothing more:

```ts
interface CaSigner {
    readonly algorithm: CaSignAlgorithm;
    getPublicKey(): Promise<ArrayBuffer>;   // SPKI DER
    sign(tbs: Uint8Array): Promise<ArrayBuffer>;
}
```

`node-opcua-pki` builds the to-be-signed bytes of each certificate and CRL locally,
then hands them to `sign()`. It never asks for the key, and a correct implementation
has no way to give it out.

## Using one

```ts
import { CertificateAuthority } from "node-opcua-pki";

const ca = new CertificateAuthority({
    keySize: 2048,
    location: "/var/pki/CA",
    subject: "/CN=Acme Issuing CA/O=Acme",
    signer: myKmsSigner
});

await ca.initialize();               // no private/cakey.pem is created
await ca.signCertificateRequest(outputFile, csrFile, params);
```

A signer implies `backend: "native"`: the `openssl` CLI can only load a key from a
file, so it cannot call out to a KMS. Passing both `signer` and `backend: "openssl"`
is a constructor error rather than a surprise at signing time.

## A Google Cloud KMS signer

```ts
import { createHash } from "node:crypto";
import { KeyManagementServiceClient } from "@google-cloud/kms";
import type { CaSigner, CaSignAlgorithm } from "node-opcua-crypto";

/** the base64 body of a PEM block, without the header, footer and newlines */
function pemBody(pem: string): string {
    return pem.replace(/-----(BEGIN|END)[^-]+-----/g, "").replace(/\s+/g, "");
}

function toArrayBuffer(buffer: Buffer): ArrayBuffer {
    return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength) as ArrayBuffer;
}

class GoogleKmsSigner implements CaSigner {
    readonly algorithm: CaSignAlgorithm = { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } };
    #client = new KeyManagementServiceClient();
    #publicKeyDer?: ArrayBuffer;

    constructor(private readonly keyVersionName: string) {}

    async getPublicKey(): Promise<ArrayBuffer> {
        // the public half never changes for a key version, so fetch it once:
        // every call is a billed round trip
        if (!this.#publicKeyDer) {
            const [publicKey] = await this.#client.getPublicKey({ name: this.keyVersionName });
            this.#publicKeyDer = toArrayBuffer(Buffer.from(pemBody(publicKey.pem!), "base64"));
        }
        return this.#publicKeyDer;
    }

    async sign(tbs: Uint8Array): Promise<ArrayBuffer> {
        // Cloud KMS signs a digest you compute, not the message itself
        const digest = createHash("sha256").update(tbs).digest();
        const [result] = await this.#client.asymmetricSign({ name: this.keyVersionName, digest: { sha256: digest } });
        return toArrayBuffer(Buffer.from(result.signature as Uint8Array));
    }
}
```

Create the key version in Cloud KMS as `RSA_SIGN_PKCS1_2048_SHA256` (or the 3072/4096
variant) so that it matches the declared `algorithm`. A mismatch produces certificates
whose signature will not verify, and nothing local can detect that for you.

The same shape works for PKCS#11 modules, AWS KMS, and Azure Key Vault: fetch the
public key once, delegate the signature.

## What changes

- **No `private/cakey.pem` is ever written.** `getPrivateKey()` and
  `reencryptPrivateKey()` throw rather than reach for a file that does not exist,
  and `privateKeyPassphrase` has nothing to protect.
- **`installCACertificate()` still verifies** that the certificate you install belongs
  to this CA. It cannot compare against a private key, so it compares the certified
  public key with the signer's. Same question, asked the way an HSM allows.
- **Every signature is a round trip.** Bootstrapping a root CA costs two (the CA
  certificate and the initial CRL); issuing a certificate costs one; revoking costs one
  for the new CRL. Cache `getPublicKey()` as above, and prefer revoking in batches over
  one CRL rebuild per certificate.
- **The on-disk layout is unchanged.** `index.txt`, `serial`, `crlnumber` and
  `certs/<SERIAL>.pem` are written exactly as `openssl ca` writes them, so external
  openssl tooling keeps working against the directory.

## Signing an externally issued CA certificate

The usual flow for a CA whose certificate is signed by someone else works unchanged,
and is the one an HSM-backed CA most often wants:

```ts
const result = await ca.initializeCSR();   // { status: "created", csrPath }
// send csrPath to the parent CA, then:
await ca.installCACertificate(signedCertFile);
```

Restarting between the two steps reports `{ status: "pending" }` and leaves the CSR
alone, so the request you sent out stays the request that gets signed.

## ECDSA signers

An ECDSA signer works the same way, and must name the curve it is on:

```ts
const signer: CaSigner = {
    algorithm: { name: "ECDSA", namedCurve: "P-256", hash: { name: "SHA-256" } },
    getPublicKey,
    sign
};
```

`namedCurve` is required because importing the signer's public key needs it, and an
SPKI import cannot infer a curve it was not given. Declaring it wrong is safe rather
than subtly broken: the SPKI bytes state the real curve, so the import fails and the
CA is refused at construction, before any directory exists.

**Signature encoding is the one thing to get right.** `sign()` must return what
`SubtleCrypto.sign` returns, which for ECDSA is the fixed-width `r || s` pair of IEEE
P1363, not the `SEQUENCE { r, s }` of DER. Certificates carry the DER form, but the
conversion happens downstream. Cloud KMS, AWS KMS and PKCS#11 tokens all return DER,
so their adapters have to convert:

```ts
import { ecdsaSignatureDerToP1363 } from "node-opcua-crypto";

async sign(tbs: Uint8Array): Promise<ArrayBuffer> {
    const [response] = await client.asymmetricSign({ name: keyName, digest: { sha256: sha256(tbs) } });
    return ecdsaSignatureDerToP1363(response.signature as Buffer, "P-256");
}
```

A signer that returns DER without converting produces a certificate whose signature
does not verify, so it is worth an explicit test rather than a code read.

### Which curves, and how that lines up with OPC UA

Supported: **P-256, P-384 and P-521**, each with SHA-256, SHA-384 or SHA-512. That set
comes from WebCrypto, which is what signs and imports keys here.

OPC UA names six ECC curves for application instance certificates (OPC 10000-12,
clauses 7.8.4.10 to 7.8.4.16, and the key-pair algorithm list in Annex F.1):

| OPC UA curve | Supported here | |
| --- | --- | --- |
| `nistP256` | yes | P-256 |
| `nistP384` | yes | P-384 |
| `brainpoolP256r1` | no | WebCrypto has no brainpool curves |
| `brainpoolP384r1` | no | " |
| `curve25519` | no | Ed25519 is a different algorithm, not ECDSA |
| `curve448` | no | " |

P-521 is supported here but is not one of the core OPC UA curves; it appears only in
the UAFX Offline profiles (OPC 10000-84, tables 57 to 59). The per-policy pairing of
curve, signature algorithm and hash lives in OPC 10000-7, whose content is published
at profiles.opcfoundation.org rather than in the PDF, so check there before assuming a
given hash is acceptable for a given curve.

The curves that are not covered are not covered *deliberately for now*: brainpool and
the Edwards curves would each need a signing path that does not go through WebCrypto.

### What this does not change

The CA's **own key** is what becomes ECDSA here. Certificates it issues take their key
from the CSR, so an EC device sending an EC CSR gets an EC certificate from either an
RSA-keyed or an EC-keyed CA. What `CertificateManager` *generates* for itself is still
RSA, so a fully EC identity has to bring its own key.

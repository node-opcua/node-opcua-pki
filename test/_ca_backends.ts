import { type CaSignAlgorithm, type CaSigner, generateKeyPair } from "node-opcua-crypto";
import { type CertificateAuthorityOptions, CertificateManager } from "node-opcua-pki";

export const RSA_SHA256: CaSignAlgorithm = { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } };
export const EC_P256_SHA256: CaSignAlgorithm = { name: "ECDSA", namedCurve: "P-256", hash: { name: "SHA-256" } };

/**
 * Stands in for a Google Cloud KMS / PKCS#11 key: it keeps the private key
 * in a closure and exposes only the two operations a real HSM offers,
 * `getPublicKey()` and `sign()`. It counts calls, so a test can prove the
 * work actually went through it rather than through some fallback path,
 * and it deliberately implements nothing else - if the CA ever reached for
 * the key material directly there would be nothing to reach.
 */
export class StubHsmSigner implements CaSigner {
    readonly algorithm: CaSignAlgorithm;
    public signCalls = 0;
    public publicKeyCalls = 0;
    readonly #keys: { privateKey: CryptoKey; publicKey: CryptoKey };

    constructor(keys: { privateKey: CryptoKey; publicKey: CryptoKey }, algorithm: CaSignAlgorithm = RSA_SHA256) {
        this.#keys = keys;
        this.algorithm = algorithm;
    }

    static async create(algorithm: CaSignAlgorithm = RSA_SHA256): Promise<StubHsmSigner> {
        // generateKeyPair() only makes RSA keys, and an EC signer has to hold
        // a key on the curve it declares or the adapter's public-key import
        // rejects it
        const keys =
            algorithm.name === "ECDSA"
                ? ((await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: algorithm.namedCurve }, true, [
                      "sign",
                      "verify"
                  ])) as { privateKey: CryptoKey; publicKey: CryptoKey })
                : await generateKeyPair();
        return new StubHsmSigner(keys, algorithm);
    }

    async getPublicKey(): Promise<ArrayBuffer> {
        this.publicKeyCalls++;
        return crypto.subtle.exportKey("spki", this.#keys.publicKey);
    }

    async sign(tbs: Uint8Array): Promise<ArrayBuffer> {
        this.signCalls++;
        return crypto.subtle.sign(this.algorithm, this.#keys.privateKey, tbs as Uint8Array<ArrayBuffer>);
    }
}

/**
 * One way of standing a CA up. Every behaviour a consumer can observe
 * through the public API is expected to hold for all of them, which is why
 * the CA suites run once per variant rather than once against whichever
 * backend happened to be the default.
 */
export interface CaBackendVariant {
    /** short, filesystem-safe - it is used to keep each variant's CA directory apart */
    name: string;
    /** false when the key lives in the signer, so `private/cakey.pem` never exists */
    keyOnDisk: boolean;
    /** whether openssl is spawned to do the signing */
    usesOpenSsl: boolean;
    /**
     * Options for one logical CA. `id` identifies which CA is being opened:
     * distinct ids get distinct keys, and reopening the same id gets the
     * same key back - which is what restarting a process against the same
     * HSM key actually looks like.
     */
    caOptions(id?: string): Promise<Partial<CertificateAuthorityOptions>>;
}

/** one key per logical CA, so reopening a CA reconnects to the key it already had */
const signersById = new Map<string, StubHsmSigner>();

async function signerFor(id: string, algorithm: CaSignAlgorithm): Promise<StubHsmSigner> {
    let signer = signersById.get(id);
    if (!signer) {
        signer = await StubHsmSigner.create(algorithm);
        signersById.set(id, signer);
    }
    return signer;
}

export const CA_BACKEND_VARIANTS: readonly CaBackendVariant[] = [
    {
        name: "openssl",
        keyOnDisk: true,
        usesOpenSsl: true,
        async caOptions() {
            return {};
        }
    },
    {
        name: "native",
        keyOnDisk: true,
        usesOpenSsl: false,
        async caOptions() {
            return { backend: "native" };
        }
    },
    {
        name: "native-signer",
        keyOnDisk: false,
        usesOpenSsl: false,
        async caOptions(id = "default") {
            return { signer: await signerFor(`rsa:${id}`, RSA_SHA256) };
        }
    },
    {
        // The CA's own key on an elliptic curve. Worth running the whole
        // suite against rather than one happy-path test, because the
        // algorithm reaches everything the CA signs - its own certificate,
        // leaves, sub-CAs and CRLs - and an RSA assumption left in any one
        // of those paths only shows up here.
        name: "native-signer-ec",
        keyOnDisk: false,
        usesOpenSsl: false,
        async caOptions(id = "default") {
            return { signer: await signerFor(`ec:${id}`, EC_P256_SHA256) };
        }
    }
];

/** A leaf CSR from a throwaway `CertificateManager`; the caller disposes it. */
export async function makeLeafCsr(
    location: string,
    params: { applicationUri: string; subject?: string; dns?: string[] }
): Promise<{ cm: CertificateManager; csr: string }> {
    const cm = new CertificateManager({ location });
    await cm.initialize();
    const csr = await cm.createCertificateRequest({
        applicationUri: params.applicationUri,
        subject: params.subject ?? "CN=Leaf",
        dns: params.dns ?? ["localhost"]
    });
    return { cm, csr };
}

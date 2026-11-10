// --------------------------------------------------------------------------
// Builds a CA, leaf certificates and CRL editions in memory, so a CRL test
// controls the CRL Number, thisUpdate, the key type and the signer.
// The CA carries a Subject Key Identifier and its leaves an Authority Key
// Identifier: CertificateManager finds an issuer by that pair.
// --------------------------------------------------------------------------
import { webcrypto } from "node:crypto";
import { exploreCertificateRevocationList, x509 } from "node-opcua-crypto";

type KeyPair = { publicKey: CryptoKey; privateKey: CryptoKey };
export type KeyType = "rsa" | "ec";

const rsa = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const ec = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
const algorithmOf = (keyType: KeyType) => (keyType === "rsa" ? rsa : ec);
export const day = 24 * 3600 * 1000;

const generateKeys = async (keyType: KeyType) =>
    (await webcrypto.subtle.generateKey(algorithmOf(keyType), true, ["sign", "verify"])) as KeyPair;

/** The DER INTEGER a CRL Number extension holds. */
function derInteger(n: bigint): Buffer {
    let hex = n.toString(16);
    if (hex.length % 2) hex = `0${hex}`;
    if (Number.parseInt(hex.slice(0, 2), 16) & 0x80) hex = `00${hex}`;
    const value = Buffer.from(hex, "hex");
    return Buffer.concat([Buffer.from([0x02, value.length]), value]);
}

export interface TestCa {
    keyType: KeyType;
    keys: KeyPair;
    certificate: x509.X509Certificate;
    /** DER of the CA certificate */
    der: Buffer;
}

export async function makeCa(commonName: string, keyType: KeyType = "rsa"): Promise<TestCa> {
    const keys = await generateKeys(keyType);
    const now = Date.now();
    const certificate = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: "01",
        name: `CN=${commonName}`,
        notBefore: new Date(now - day),
        notAfter: new Date(now + 365 * day),
        keys,
        signingAlgorithm: algorithmOf(keyType),
        extensions: [
            new x509.BasicConstraintsExtension(true, undefined, true),
            new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
            await x509.SubjectKeyIdentifierExtension.create(keys.publicKey)
        ]
    });
    return { keyType, keys, certificate, der: Buffer.from(certificate.rawData) };
}

export async function makeLeaf(ca: TestCa, serialNumber: string): Promise<Buffer> {
    const now = Date.now();
    const leaf = await x509.X509CertificateGenerator.create({
        serialNumber,
        subject: `CN=leaf ${serialNumber}`,
        issuer: ca.certificate.subjectName,
        notBefore: new Date(now - day),
        notAfter: new Date(now + 300 * day),
        publicKey: (await generateKeys(ca.keyType)).publicKey,
        signingKey: ca.keys.privateKey,
        signingAlgorithm: algorithmOf(ca.keyType),
        extensions: [await x509.AuthorityKeyIdentifierExtension.create(ca.keys.publicKey)]
    });
    return Buffer.from(leaf.rawData);
}

export async function makeCrl(
    ca: TestCa,
    options: {
        crlNumber?: bigint;
        thisUpdate: Date;
        revoked: Buffer[];
        signingKey?: CryptoKey;
        /** false: no nextUpdate (OPTIONAL in RFC 5280's TBSCertList) */
        nextUpdate?: false;
    }
): Promise<Buffer> {
    const crl = await x509.X509CrlGenerator.create({
        issuer: ca.certificate.subjectName,
        thisUpdate: options.thisUpdate,
        nextUpdate: options.nextUpdate === false ? undefined : new Date(options.thisUpdate.getTime() + 30 * day),
        entries: options.revoked.map((c) => ({
            serialNumber: new x509.X509Certificate(c).serialNumber,
            revocationDate: options.thisUpdate
        })),
        extensions: options.crlNumber === undefined ? [] : [new x509.Extension("2.5.29.20", false, derInteger(options.crlNumber))],
        signingKey: options.signingKey ?? ca.keys.privateKey,
        signingAlgorithm: algorithmOf(ca.keyType)
    });
    return Buffer.from(crl.rawData);
}

/** A private key that is not the CA's, to forge a CRL in its name. */
export async function makeForgerKey(keyType: KeyType = "rsa"): Promise<CryptoKey> {
    return (await generateKeys(keyType)).privateKey;
}

/** The slot addRevocationList writes the CRL of this issuer to. */
export function slotOf(crl: Buffer, extension = ".crl"): string {
    return `crl_[${exploreCertificateRevocationList(crl).tbsCertList.issuerFingerprint.replace(/:/g, "")}]${extension}`;
}

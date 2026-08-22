// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-pki
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2026 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2026 - Sterfive.com
// ---------------------------------------------------------------------------------------------------------------------
//
// This  project is licensed under the terms of the MIT license.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so,  subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// ---------------------------------------------------------------------------------------------------------------------

import fs from "node:fs";
import path from "node:path";
import {
    type CaSignAlgorithm,
    type CaSigner,
    CertificatePurpose,
    createCertificateFromCsr,
    createCertificateSigningRequest,
    createCrl,
    isCaSigner,
    privateKeyToCryptoKey,
    readPrivateKey,
    Subject,
    x509
} from "node-opcua-crypto";
import { displaySubtitle, displayTitle, type Params, type ProcessAltNamesParam } from "../../toolbox";
import type { CaBackend } from "../core/ca_backend";
import { CaDatabase } from "../core/ca_database";
import type { CertificateAuthorityCore } from "../core/certificate_authority_core";

/** The CA-certificate lifetime the openssl backend hard-codes (`x509 -req -days 3650`). */
const CA_CERT_VALIDITY_DAYS = 3650;

const RSA_SHA256: CaSignAlgorithm = { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } };

/** A signer declares its own algorithm; a raw key is always the RSA/SHA-256 this CA generates. */
function signingAlgorithmOf(key: CryptoKey | CaSigner): CaSignAlgorithm {
    return isCaSigner(key) ? key.algorithm : RSA_SHA256;
}

function daysFromNow(notBefore: Date, days: number): Date {
    return new Date(notBefore.getTime() + days * 24 * 60 * 60 * 1000);
}

/**
 * The SAN every CA certificate carries. RFC 5280 does not require one on a
 * CA certificate, but the OPC UA profile does, and validators (UaExpert,
 * the compliance tools) reject a CA without it - so mirror what the
 * openssl backend puts in `[v3_ca]`: `URI:urn:<commonName>`.
 */
function caSanUri(ca: CertificateAuthorityCore): string {
    return `urn:${ca.subject.commonName || "NodeOPCUA-CA"}`;
}

/**
 * The subject alternative names a CSR asked for, in the shape the signing
 * primitive wants. `openssl ca` does not copy SANs across from the CSR
 * (openssl/openssl#10458), which is why the caller has to re-derive them;
 * peculiar decodes IP addresses to dotted form for us.
 */
function sanFromCsr(csrPem: string): { dns: string[]; ip: string[]; applicationUri?: string } {
    const request = new x509.Pkcs10CertificateRequest(csrPem);
    const extension = request.getExtension("2.5.29.17") as x509.SubjectAlternativeNameExtension | null;
    const dns: string[] = [];
    const ip: string[] = [];
    let applicationUri: string | undefined;
    for (const name of extension?.names.toJSON() ?? []) {
        if (name.type === "dns") {
            dns.push(name.value);
        } else if (name.type === "ip") {
            ip.push(name.value);
        } else if (name.type === "url" && applicationUri === undefined) {
            applicationUri = name.value;
        }
    }
    return { dns, ip, applicationUri };
}

/**
 * Maps this codebase's CRL revocation reason strings (see
 * `CertificateAuthority.revokeCertificate`'s `crlReasons` list) to
 * `@peculiar/x509`'s `X509CrlReason` enum keys — same reasons, but
 * `X509CrlReason.cACompromise` is lowercase-first where this codebase's
 * `"CACompromise"` is not.
 */
const REASON_TO_X509_CRL_REASON: Record<string, x509.X509CrlReason> = {
    unspecified: x509.X509CrlReason.unspecified,
    keyCompromise: x509.X509CrlReason.keyCompromise,
    CACompromise: x509.X509CrlReason.cACompromise,
    affiliationChanged: x509.X509CrlReason.affiliationChanged,
    superseded: x509.X509CrlReason.superseded,
    cessationOfOperation: x509.X509CrlReason.cessationOfOperation,
    certificateHold: x509.X509CrlReason.certificateHold,
    removeFromCRL: x509.X509CrlReason.removeFromCRL
};

/**
 * Builds OpenSSL's slash-delimited one-line subject (`"/CN=Leaf/O=Acme"`)
 * from the certificate's parsed subject attributes — NOT by re-splitting
 * `Name.toString()`. The subject comes verbatim from the requester's CSR,
 * so it is attacker-controlled; the string form escapes `,` (which a
 * `split(",")` would then mangle) and, because its control-character
 * `replace()` has no `g` flag, escapes only the FIRST `\n`/`\t` per value,
 * letting later ones through raw — which would let a crafted CN inject a
 * forged row into the tab/newline-delimited `index.txt`. Working from
 * `toJSON()` sidesteps that entirely; {@link CaDatabase} additionally
 * escapes every control character it writes, as `X509_NAME_oneline` does.
 */
function toOpenSslSubjectString(subjectName: x509.Name): string {
    const parts: string[] = [];
    for (const rdn of subjectName.toJSON()) {
        for (const [type, values] of Object.entries(rdn)) {
            for (const value of values) {
                parts.push(`${type}=${value}`);
            }
        }
    }
    return `/${parts.join("/")}`;
}

/**
 * A native (pure-JS, no `openssl` child process) {@link CaBackend}: it
 * bootstraps a CA, signs end-entity and subordinate-CA requests, revokes,
 * and builds CRLs entirely through `node-opcua-crypto`'s signing
 * primitives and {@link CaDatabase}'s write path, so the resulting
 * `index.txt`/`serial`/`crlnumber`/`certs/` are the same on-disk format
 * `openssl ca` produces and an install can move between backends.
 *
 * The signing key reaches every operation through
 * `CertificateAuthority._getSigningKey()`, which yields either the on-disk
 * key or an external `CaSigner`. Nothing below can tell the difference,
 * which is the point: a CA whose key lives in an HSM never has a
 * `private/cakey.pem` and never needs one.
 *
 * Two deliberate differences from the openssl backend, both improvements:
 * a subordinate CA's certificate is recorded in the issuer's `index.txt`
 * (`openssl x509 -CAserial` bumps the serial file but records nothing),
 * and a subordinate's SAN is taken from its own CSR rather than being
 * stamped with the issuer's.
 */
export class NativeCaBackend implements CaBackend {
    /** Nothing to check: this backend spawns no process and needs no tool on PATH. */
    /** Signing goes through `ca._getSigningKey()`, which may be an external signer. */
    public readonly supportsExternalSigner = true;

    public async preflight(): Promise<void> {
        // intentionally empty
    }

    /**
     * Write a CSR for the CA's own key, the `[v3_ca_req]` equivalent. The
     * key comes from the CA rather than from `privateKeyFile`: on a
     * signer-backed CA that file does not exist.
     */
    public async generateCaCsr(
        ca: CertificateAuthorityCore,
        _caRootDir: string,
        _privateKeyFile: string,
        csrFile: string
    ): Promise<void> {
        displayTitle("Generate a certificate request for the CA key");
        const signingKey = await ca._getSigningKey();
        const { csr } = await createCertificateSigningRequest({
            privateKey: signingKey,
            subject: ca.subject.toString(),
            applicationUri: caSanUri(ca),
            purpose: CertificatePurpose.ForCertificateAuthority
        });
        await fs.promises.writeFile(csrFile, csr);
    }

    public async bootstrap(ca: CertificateAuthorityCore): Promise<void> {
        const caRootDir = path.resolve(ca.rootDir);
        const csrFile = path.join(caRootDir, "private/cakey.csr");
        await this.generateCaCsr(ca, caRootDir, path.join(caRootDir, "private/cakey.pem"), csrFile);

        const issuerCA = ca._issuerCA;
        if (issuerCA) {
            displayTitle("Generate CA Certificate (signed by issuer CA)");
            // The issuer's serial file and database are mutated here, so the
            // issuer's own lock is required - the caller only holds this
            // (subordinate) CA's. Subordinate -> issuer is the only cross-CA
            // lock edge in this codebase and it is never reversed, so it
            // cannot deadlock; the exception is two CAs sharing one rootDir,
            // where the lock is already held and re-acquiring the
            // non-reentrant file lock would deadlock against itself.
            const signWithIssuer = () => this.signSubordinateCsr(issuerCA, csrFile, ca.caCertificate, CA_CERT_VALIDITY_DAYS);
            if (path.resolve(issuerCA.rootDir) === caRootDir) {
                await signWithIssuer();
            } else {
                await issuerCA._withCaDirectoryLock(signWithIssuer);
            }
        } else {
            displayTitle("Generate CA Certificate (self-signed)");
            const csrPem = await fs.promises.readFile(csrFile, "utf-8");
            const signingKey = await ca._getSigningKey();
            const request = new x509.Pkcs10CertificateRequest(csrPem);
            const notBefore = new Date();
            const { cert } = await createCertificateFromCsr({
                csr: csrPem,
                // the CSR's own parsed subject, so issuer and subject are
                // byte-identical on a self-signed root: re-encoding a string
                // form could differ and break chain building
                issuerName: request.subjectName,
                issuerPublicKey: request.publicKey,
                signingKey,
                signingAlgorithm: signingAlgorithmOf(signingKey),
                notBefore,
                notAfter: daysFromNow(notBefore, CA_CERT_VALIDITY_DAYS),
                purpose: CertificatePurpose.ForCertificateAuthority,
                applicationUri: caSanUri(ca),
                revocation: {
                    crlDistributionUrl: ca.crlDistributionUrl,
                    ocspResponderUrl: ca.ocspResponderUrl,
                    caIssuersUrl: ca.caIssuersUrl
                }
            });
            await fs.promises.writeFile(ca.caCertificate, cert);
        }

        displaySubtitle("generate initial CRL (Certificate Revocation List)");
        await this.#regenerateCrlLocked(ca, new CaDatabase(ca.rootDir));
        displayTitle("Create Certificate Authority (CA) ---> DONE");
    }

    /** Sign a subordinate CA's request with this CA's key, the `[v3_ca]` equivalent. */
    public async signSubordinateCsr(
        ca: CertificateAuthorityCore,
        csrFile: string,
        certFile: string,
        validityDays: number
    ): Promise<void> {
        const { signingKey, signingAlgorithm, issuerPublicKey, issuerName } = await this.#issuerContext(ca);
        const csrPem = await fs.promises.readFile(csrFile, "utf-8");
        const db = new CaDatabase(ca.rootDir);
        const serialNumber = db.nextSerial();
        const notBefore = new Date();
        const notAfter = daysFromNow(notBefore, validityDays);

        const { cert } = await createCertificateFromCsr({
            csr: csrPem,
            issuerName,
            issuerPublicKey,
            signingKey,
            signingAlgorithm,
            serialNumber,
            notBefore,
            notAfter,
            purpose: CertificatePurpose.ForCertificateAuthority,
            // the subordinate's own SAN, not the issuer's
            ...sanFromCsr(csrPem),
            revocation: {
                crlDistributionUrl: ca.crlDistributionUrl,
                ocspResponderUrl: ca.ocspResponderUrl,
                caIssuersUrl: ca.caIssuersUrl
            }
        });

        await fs.promises.writeFile(certFile, cert);
        this.#record(db, serialNumber, cert, notAfter);
    }

    /**
     * Self-sign a certificate with a caller-supplied key file and record it
     * in this CA's database: the native equivalent of `openssl req -new`
     * followed by `openssl ca -selfsign`, which likewise applies the
     * end-entity profile and updates `index.txt`.
     */
    public async createSelfSignedCertificate(
        ca: CertificateAuthorityCore,
        certificateFile: string,
        privateKeyFile: string,
        params: Params
    ): Promise<void> {
        displaySubtitle("- the certificate signing request");
        const key = await privateKeyToCryptoKey(readPrivateKey(privateKeyFile, await ca._privateKeyPassphrase()));
        const { csr } = await createCertificateSigningRequest({
            privateKey: key,
            subject: params.subject ? new Subject(params.subject).toString() : ca.subject.toString(),
            dns: params.dns,
            ip: params.ip,
            applicationUri: params.applicationUri,
            purpose: CertificatePurpose.ForApplication
        });

        displaySubtitle("- creating the self-signed certificate");
        const request = new x509.Pkcs10CertificateRequest(csr);
        const db = new CaDatabase(ca.rootDir);
        const serialNumber = db.nextSerial();
        const notBefore = params.startDate ?? new Date();
        const notAfter = params.endDate ?? daysFromNow(notBefore, params.validity ?? 365);

        const { cert } = await createCertificateFromCsr({
            csr,
            issuerName: request.subjectName,
            issuerPublicKey: request.publicKey,
            signingKey: key,
            signingAlgorithm: RSA_SHA256,
            serialNumber,
            notBefore,
            notAfter,
            purpose: CertificatePurpose.ForApplication,
            ...sanFromCsr(csr)
        });

        await fs.promises.writeFile(certificateFile, cert);
        this.#record(db, serialNumber, cert, notAfter);
    }

    /** `certs/<SERIAL>.pem` plus the `V` row, exactly as `openssl ca` writes them. */
    #record(db: CaDatabase, serialNumber: string, certPem: string, notAfter: Date): void {
        db.storeCertificate(serialNumber, certPem);
        db.appendIssued({
            serial: serialNumber,
            expiryDate: notAfter,
            subject: toOpenSslSubjectString(new x509.X509Certificate(certPem).subjectName)
        });
    }

    /**
     * The CA's signing key and issuer identity, resolved fresh on every
     * call and never cached across operations. The identity is read back
     * from the CA certificate on disk so that the issuer field of anything
     * this CA signs is byte-identical to that certificate's subject.
     */
    async #issuerContext(ca: CertificateAuthorityCore): Promise<{
        signingKey: CryptoKey | CaSigner;
        signingAlgorithm: CaSignAlgorithm;
        issuerPublicKey: x509.PublicKey;
        issuerName: x509.Name;
    }> {
        const signingKey = await ca._getSigningKey();
        const caCertPem = await fs.promises.readFile(ca.caCertificate, "utf-8");
        const caCert = new x509.X509Certificate(caCertPem);
        return {
            signingKey,
            signingAlgorithm: signingAlgorithmOf(signingKey),
            issuerPublicKey: caCert.publicKey,
            issuerName: caCert.subjectName
        };
    }

    public async signEndEntityCsr(
        ca: CertificateAuthorityCore,
        certificate: string,
        csr: string,
        params: Params,
        sanOverride: Required<ProcessAltNamesParam>
    ): Promise<void> {
        const { signingKey, signingAlgorithm, issuerPublicKey, issuerName } = await this.#issuerContext(ca);
        const db = new CaDatabase(ca.rootDir);
        const serialNumber = db.nextSerial();
        const csrPem = await fs.promises.readFile(csr, "utf-8");

        const notBefore = params.startDate ?? new Date();
        const notAfter = params.endDate ?? new Date(notBefore.getTime() + (params.validity ?? 365) * 24 * 60 * 60 * 1000);

        const { cert } = await createCertificateFromCsr({
            csr: csrPem,
            issuerName,
            issuerPublicKey,
            signingKey,
            signingAlgorithm,
            serialNumber,
            notBefore,
            notAfter,
            purpose: CertificatePurpose.ForApplication,
            dns: sanOverride.dns,
            ip: sanOverride.ip,
            applicationUri: sanOverride.applicationUri,
            revocation: {
                crlDistributionUrl: ca.crlDistributionUrl,
                ocspResponderUrl: ca.ocspResponderUrl,
                caIssuersUrl: ca.caIssuersUrl
            }
        });

        await fs.promises.writeFile(certificate, cert);
        this.#record(db, serialNumber, cert, notAfter);
    }

    async #regenerateCrlLocked(ca: CertificateAuthorityCore, db: CaDatabase): Promise<void> {
        const { signingKey, signingAlgorithm, issuerPublicKey, issuerName } = await this.#issuerContext(ca);
        const crlNumber = db.nextCrlNumber();
        const entries = db
            .readIndex()
            .filter((r) => r.status === "revoked")
            .map((r) => ({
                serialNumber: r.serial,
                revocationDate: r.revocationDate ? new Date(r.revocationDate) : new Date(),
                reason: r.reason ? REASON_TO_X509_CRL_REASON[r.reason] : undefined
            }));

        const { crl } = await createCrl({
            issuerName,
            issuerPublicKey,
            signingKey,
            signingAlgorithm,
            crlNumber: BigInt(`0x${crlNumber}`),
            entries
        });

        await fs.promises.writeFile(ca.revocationList, crl);
        const der = new x509.X509Crl(crl).rawData;
        await fs.promises.writeFile(ca.revocationListDER, Buffer.from(der));
    }

    public async regenerateCrl(ca: CertificateAuthorityCore): Promise<void> {
        const db = new CaDatabase(ca.rootDir);
        await this.#regenerateCrlLocked(ca, db);
    }

    public async revoke(ca: CertificateAuthorityCore, certificate: string, reason: string): Promise<void> {
        const certPem = await fs.promises.readFile(certificate, "utf-8");
        const cert = new x509.X509Certificate(certPem);
        const db = new CaDatabase(ca.rootDir);
        db.markRevoked(cert.serialNumber, new Date(), reason);
        await this.#regenerateCrlLocked(ca, db);
    }
}

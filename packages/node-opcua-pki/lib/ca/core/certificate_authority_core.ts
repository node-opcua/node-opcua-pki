// ---------------------------------------------------------------------------------------------------------------------
// node-opcua
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
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { withLock } from "@ster5/global-mutex";
import chalk from "chalk";
import {
    type CaSigner,
    CertificatePurpose,
    certificateMatchesPrivateKey,
    convertPEMtoDER,
    createCertificateSigningRequest,
    createPfx,
    exploreCertificate,
    exploreCertificateSigningRequest,
    generatePrivateKeyFile,
    type PrivateKey,
    privateKeyToCryptoKey,
    readCertificatePEM,
    readCertificateSigningRequest,
    readPrivateKey,
    Subject,
    type SubjectOptions,
    toPem,
    verifyCertificateSignature,
    writePrivateKeyFile,
    x509
} from "node-opcua-crypto";
import {
    adjustApplicationUri,
    adjustDate,
    certificateFileExist,
    debugLog,
    displaySubtitle,
    displayTitle,
    ensurePrivateDirectory,
    type Filename,
    isEncryptedPrivateKeyFile,
    type KeySize,
    makePath,
    mkdirRecursiveSync,
    type Params,
    type PrivateKeyPassphrase,
    type ProcessAltNamesParam,
    resolvePrivateKeyPassphrase,
    restrictPrivateFilePermissions,
    warningLog
} from "../../toolbox";
import type { CaBackend } from "./ca_backend";
import { CaDatabase, type IssuedCertificateRecord } from "./ca_database";

/** Default X.500 subject used when no custom subject is provided. */
export const defaultSubject = "/C=FR/ST=IDF/L=Paris/O=Local NODE-OPCUA Certificate Authority/CN=NodeOPCUA-CA";

import _ca_config_template from "../templates/ca_config_template.cnf";

export const configurationFileTemplate: string = _ca_config_template;

/**
 * Escape a value for use inside a double-quoted openssl config value.
 *
 * openssl's config parser (crypto/conf/conf_def.c) treats an unquoted value
 * specially: `$var` / `${var}` / `$(var)` are expanded, and `'`, `"` and the
 * backtick are all quote characters (a backtick pair is silently removed).
 * Inside a double-quoted value none of that applies: characters are copied
 * verbatim except a backslash, which escapes the next character. So a path
 * containing `$`, backticks, `#` or spaces is safe once double-quoted with
 * `\` and `"` escaped.
 */
export function escapeOpensslConfDoubleQuoted(value: string): string {
    return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

/**
 * Render the CA openssl configuration for `caRootDir`. The root folder is
 * emitted forward-slashed (openssl accepts that on every platform) and
 * double-quoted, so a CA `location` containing characters that openssl's
 * config syntax would otherwise interpret (`$`, backticks, `#`, quotes) is
 * taken literally.
 */
export function renderCaConfig(caRootDir: string): string {
    return configurationFileTemplate.replace(/%%ROOT_FOLDER%%/, escapeOpensslConfDoubleQuoted(makePath(caRootDir)));
}

const config = {
    certificateDir: "INVALID",
    forceCA: false,
    pkiDir: "INVALID"
};

/**
 * Upper bound on how long a CA operation waits for `.ca.lock` before
 * throwing. CA operations themselves complete in seconds; a dead holder's
 * lock goes stale and is taken over after ~2 minutes, so 5 minutes covers
 * every legitimate wait with margin while still turning a stuck holder
 * into a loud error instead of a silent fleet-wide hang.
 */
const CA_LOCK_MAX_WAIT_MS = 5 * 60_000;

/**
 * How long a waiter sleeps between attempts at the CA directory lock.
 * The lock library's default backoff doubles without an upper bound, so a
 * queue of contending operations ends up sleeping through 1s, 2s, 4s, 8s,
 * 16s ... while the lock is in fact free again after milliseconds: eight
 * queued signings measured over two minutes. Capping the interval keeps a
 * freed lock from going unnoticed; `CA_LOCK_MAX_WAIT_MS` still bounds the
 * total wait.
 */
const CA_LOCK_RETRY = { minTimeout: 20, maxTimeout: 250 };

// convert 'c07b9179'  to    "192.123.145.121"
function octetStringToIpAddress(a: string) {
    return (
        parseInt(a.substring(0, 2), 16).toString() +
        "." +
        parseInt(a.substring(2, 4), 16).toString() +
        "." +
        parseInt(a.substring(4, 6), 16).toString() +
        "." +
        parseInt(a.substring(6, 8), 16).toString()
    );
}
assert(octetStringToIpAddress("c07b9179") === "192.123.145.121");

/**
 * Result of {@link CertificateAuthority.initializeCSR}.
 *
 * - `"ready"` — the CA certificate already exists and is valid.
 * - `"pending"` — key + CSR exist but no cert; waiting for external signing.
 * - `"created"` — a fresh key + CSR were just generated.
 * - `"expired"` — the CA certificate has expired (or will expire within
 *   the configured threshold). A new CSR has been generated for renewal
 *   while preserving the existing private key.
 */
export type InitializeCSRResult =
    | { status: "ready" }
    | { status: "pending"; csrPath: string }
    | { status: "created"; csrPath: string }
    | { status: "expired"; csrPath: string; expiryDate: Date };

/**
 * Result of {@link CertificateAuthority.installCACertificate}.
 *
 * - `"success"` — the certificate was installed and CRL generated.
 * - `"error"` — the certificate was rejected (see `reason`).
 */
export type InstallCACertificateResult = { status: "success" } | { status: "error"; reason: string; message: string };

/**
 * Options for creating a {@link CertificateAuthority}.
 */
export interface CertificateAuthorityCoreOptions {
    /** RSA key size for the CA private key. */
    keySize: KeySize;
    /** Filesystem path where the CA directory structure is stored. */
    location: string;
    /**
     * X.500 subject for the CA certificate.
     * Accepts a slash-delimited string (e.g. `"/CN=My CA/O=Acme"`) or
     * a structured {@link SubjectOptions} object.
     *
     * @defaultValue {@link defaultSubject}
     */
    subject?: string | SubjectOptions;
    /**
     * Parent CA that will sign this CA's certificate.
     * If omitted, the CA is self-signed (root CA).
     * The parent CA must be initialized before this CA.
     */
    issuerCA?: CertificateAuthorityCore;
    /**
     * Public URL (http/https) where the CRL produced by this CA is
     * reachable. When set, every issued certificate carries an
     * X.509v3 `crlDistributionPoints` extension pointing at this URL.
     *
     * Leave undefined to omit the extension entirely (opt-in — see
     * US-202).  Validated synchronously at construction / setter call.
     */
    crlDistributionUrl?: string;
    /**
     * Public URL of the OCSP responder. When set, every issued cert
     * carries an `authorityInfoAccess` extension with an `OCSP` leg
     * pointing at this URL. Leave undefined to omit (US-202).
     */
    ocspResponderUrl?: string;
    /**
     * Public URL where the issuer's certificate can be fetched.
     * When set, the `authorityInfoAccess` extension on every issued
     * cert carries a `caIssuers` leg pointing at this URL (chain
     * repair). Leave undefined to omit (US-202).
     */
    caIssuersUrl?: string;
    /**
     * Encrypt the CA private key (`private/cakey.pem`) at rest with this
     * passphrase (opt-in, default off). When set:
     * - a freshly generated CA key is written as encrypted PKCS#8;
     * - an existing *plaintext* CA key is encrypted in place by
     *   {@link CertificateAuthority.initialize} / `initializeCSR()`;
     * - every `openssl` invocation that loads the CA key (CSR, self-sign,
     *   sign, revoke, CRL generation) receives it via `-passin env:`, never
     *   in argv; a missing or wrong passphrase fails `initialize()` closed.
     *
     * A function is called at most once per instance; the resolved
     * passphrase is kept in memory for the instance's lifetime because the
     * CA hands it to each openssl child. Never logged.
     *
     * A subordinate CA (`issuerCA` set) uses the *issuer's* passphrase for
     * the issuer's key: construct the parent with its own option.
     */
    privateKeyPassphrase?: PrivateKeyPassphrase;
    /**
     * Who actually signs, and writes the certificate database. Supplying it
     * is the whole point of this class: nothing here names a concrete
     * backend, so a program that only ever uses the native one never
     * references - and never has to ship - the openssl one.
     *
     * {@link CertificateAuthority} is the batteries-included subclass that
     * picks a backend for you from a `"openssl" | "native"` option.
     */
    backend: CaBackend;
    /**
     * Sign with an external key that never leaves its holder - an HSM or a
     * cloud KMS - instead of `private/cakey.pem`. The signer exposes only
     * `getPublicKey()` and `sign(tbs)`; this class builds the to-be-signed
     * bytes locally and asks the signer for the signature.
     *
     * Setting this implies `backend: "native"` (the openssl CLI can only
     * load a key from a file, so it cannot honour a signer); combining it
     * with an explicit `backend: "openssl"` is a constructor error. No
     * `private/cakey.pem` is generated, and the key-file operations that
     * cannot apply - {@link CertificateAuthority.getPrivateKey} and
     * {@link CertificateAuthority.reencryptPrivateKey} - throw.
     */
    signer?: CaSigner;
}

/**
 * An OpenSSL-based Certificate Authority (CA) that can create,
 * sign, and revoke X.509 certificates.
 *
 * The CA maintains a standard OpenSSL directory layout under
 * {@link CertificateAuthority.rootDir | rootDir}:
 *
 * ```
 * <location>/
 *   ├── conf/           OpenSSL configuration
 *   ├── private/        CA private key (cakey.pem)
 *   ├── public/         CA certificate  (cacert.pem)
 *   ├── certs/          Signed certificates
 *   ├── crl/            Revocation lists
 *   ├── serial          Next serial number
 *   ├── crlnumber       Next CRL number
 *   └── index.txt       Certificate database
 * ```
 *
 * @example
 * ```ts
 * const ca = new CertificateAuthority({
 *     keySize: 2048,
 *     location: "/var/pki/CA"
 * });
 * await ca.initialize();
 * ```
 */

// ---------------------------------------------------------------
// Certificate database types (US-057)
// ---------------------------------------------------------------

export type { IssuedCertificateRecord };

/**
 * Options for {@link CertificateAuthority.signCertificateRequestFromDER}.
 *
 * All fields are optional. When provided, they override the
 * corresponding values from the CSR.
 */
export interface SignCertificateOptions {
    /** Certificate validity in days (default: 365). */
    validity?: number;
    /**
     * Certificate validity in milliseconds.
     *
     * When provided, takes precedence over {@link validity} and enables
     * sub-day validity (e.g. 10-minute certificates for renewal demos).
     */
    validityMs?: number;
    /** Override the certificate start date. */
    startDate?: Date;
    /** Override DNS SANs. */
    dns?: string[];
    /** Override IP SANs. */
    ip?: string[];
    /** Override the application URI SAN. */
    applicationUri?: string;
    /** Override the X.500 subject. */
    subject?: SubjectOptions | string;
}

/**
 * Capabilities advertised by a PKI backend (or by this
 * {@link CertificateAuthority}) so consumers can clamp requested
 * validity to the limits the backend can actually honor.
 *
 * Useful for the GDS Pull / Push management flows, where the CA may
 * be supplied by an external service (step-ca, EJBCA, …) with its
 * own minimum / maximum / granularity constraints.
 *
 * @see CertificateAuthority.getCapabilities
 */
export interface PkiBackendCapabilities {
    /** Smallest validity this backend can issue, in milliseconds. */
    minValidityMs: number;
    /** Largest validity this backend will issue, in milliseconds. */
    maxValidityMs: number;
    /**
     * Validity is rounded up to the nearest multiple of this many
     * milliseconds. For `node-opcua-pki`'s OpenSSL-based CA this is
     * 1 000 ms (one second — the X.509 floor per RFC 5280 §4.1.2.5).
     */
    validityGranularityMs: number;
    /**
     * Native unit the backend works in. Diagnostic only — callers
     * always pass `validityMs` (US-208 / US-210).
     */
    nativeUnit: "second" | "minute" | "hour" | "day";
}

/**
 * Options for {@link CertificateAuthority.generateKeyPairAndSignDER}.
 */
export interface GenerateKeyPairAndSignOptions {
    /** OPC UA application URI (required). */
    applicationUri: string;
    /** X.500 subject for the certificate (e.g. "CN=MyApp"). */
    subject?: SubjectOptions | string;
    /** DNS host names for the SAN extension. */
    dns?: string[];
    /** IP addresses for the SAN extension. */
    ip?: string[];
    /** Certificate validity in days (default: 365). */
    validity?: number;
    /**
     * Certificate validity in milliseconds.
     *
     * When provided, takes precedence over {@link validity} and enables
     * sub-day validity (e.g. 10-minute certificates for renewal demos).
     */
    validityMs?: number;
    /** Certificate start date (default: now). */
    startDate?: Date;
    /** RSA key size in bits (default: 2048). */
    keySize?: KeySize;
}

/**
 * Options for {@link CertificateAuthority.generateKeyPairAndSignPFX}.
 *
 * Extends the DER options with an optional `passphrase` to protect
 * the PFX bundle.
 */
export interface GenerateKeyPairAndSignPFXOptions extends GenerateKeyPairAndSignOptions {
    /**
     * Passphrase to protect the PFX file.
     * If omitted, the PFX is created without a password.
     */
    passphrase?: string;
}

/**
 * Synchronously validate a revocation-related URL (CDP / OCSP /
 * caIssuers) before it is stored on a {@link CertificateAuthority}.
 *
 * Rules:
 * - `undefined` is a valid input — the matching extension is omitted.
 * - Empty string throws (almost always a config bug — pass `undefined`).
 * - Must parse via `new URL(s)`.
 * - Protocol must be `http:` or `https:`.
 * - Must include a non-trivial path (not `""` or `"/"`).
 * - Loopback hostname produces a warning but does not throw — useful
 *   for tests and local dev where pki-server and relying party share
 *   a host.
 *
 * @see US-202
 */
function validateRevocationUrl(url: string | undefined, fieldName: string): string | undefined {
    if (url === undefined) {
        return undefined;
    }
    if (url === "") {
        throw new Error(`${fieldName} must not be empty — pass undefined to disable the extension`);
    }
    let parsed: URL;
    try {
        parsed = new URL(url);
    } catch {
        throw new Error(`${fieldName} is not a valid URL: ${url}`);
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        throw new Error(`${fieldName} must use http: or https: (got ${parsed.protocol} in ${url})`);
    }
    if (!parsed.pathname || parsed.pathname === "/") {
        throw new Error(`${fieldName} must include a path component (got ${url})`);
    }
    const isLoopback = parsed.hostname === "localhost" || parsed.hostname === "::1" || parsed.hostname.startsWith("127.");
    if (isLoopback) {
        console.warn(
            `[node-opcua-pki] ${fieldName} points at loopback (${url}) — ` +
                "certificates issued with this URL will be unreachable from any other host."
        );
    }
    return url;
}

export class CertificateAuthorityCore {
    /** RSA key size used when generating the CA private key. */
    public readonly keySize: KeySize;
    /** Root filesystem path of the CA directory structure. */
    public readonly location: string;
    /** X.500 subject of the CA certificate. */
    public readonly subject: Subject;

    /** @internal Parent CA (undefined for root CAs). */
    readonly _issuerCA?: CertificateAuthorityCore;

    /** @internal Configured CDP / AIA URLs (US-202). */
    private _crlDistributionUrl?: string;
    private _ocspResponderUrl?: string;
    private _caIssuersUrl?: string;

    readonly #privateKeyPassphrase?: PrivateKeyPassphrase;
    /** resolved once (see `privateKeyPassphrase`); `#passphraseResolved` distinguishes "none" from "not yet" */
    #resolvedPassphrase?: string;
    #passphraseResolved = false;

    /** Signing backend: `openssl` shells out to the CLI, `native` signs in-process. */
    readonly #backend: CaBackend;
    /** External signing key (HSM/KMS), when one was supplied instead of a key file. */
    readonly #signer?: CaSigner;
    /** Read access to `index.txt` / `certs/<SERIAL>.pem`. */
    readonly #db: CaDatabase;

    constructor(options: CertificateAuthorityCoreOptions) {
        assert(Object.prototype.hasOwnProperty.call(options, "location"));
        assert(Object.prototype.hasOwnProperty.call(options, "keySize"));
        this.location = options.location;
        this.keySize = options.keySize || 2048;
        this.subject = new Subject(options.subject || defaultSubject);
        this._issuerCA = options.issuerCA;
        this.#privateKeyPassphrase = options.privateKeyPassphrase;
        this.#signer = options.signer;
        if (options.signer) {
            // Refuse a signer nothing can use here, where the message can say
            // what is wrong with it, rather than letting it surface as a
            // normalize-algorithm error thrown from inside WebCrypto once the
            // CA directory already exists. The type system says as much for
            // TypeScript callers, but a signer is exactly the sort of object
            // that arrives from untyped glue around a KMS SDK.
            const algorithm = options.signer.algorithm;
            if (algorithm.name !== "RSASSA-PKCS1-v1_5" && algorithm.name !== "ECDSA") {
                throw new Error(
                    `CertificateAuthority: signer algorithm ${(algorithm as { name: string }).name} is not supported - ` +
                        "use RSASSA-PKCS1-v1_5 or ECDSA."
                );
            }
            if (algorithm.name === "ECDSA" && !algorithm.namedCurve) {
                throw new Error(
                    "CertificateAuthority: an ECDSA signer must declare its namedCurve (P-256, P-384 or P-521) - " +
                        "importing the signer's public key needs the curve, and an SPKI import cannot infer it."
                );
            }
        }
        if (options.signer && !options.backend.supportsExternalSigner) {
            // asked of the backend rather than hardcoded here, so this class
            // keeps working for backends it has never heard of
            throw new Error(
                "CertificateAuthority: this backend cannot sign with an external signer - " +
                    "it loads its key from a file. Use a backend that supports one, such as NativeCaBackend."
            );
        }
        this.#backend = options.backend;
        this.#db = new CaDatabase(this.location);
        if (options.crlDistributionUrl !== undefined) {
            this.setCrlDistributionUrl(options.crlDistributionUrl);
        }
        if (options.ocspResponderUrl !== undefined) {
            this.setOcspResponderUrl(options.ocspResponderUrl);
        }
        if (options.caIssuersUrl !== undefined) {
            this.setCaIssuersUrl(options.caIssuersUrl);
        }
    }

    /**
     * Public URL where the CRL produced by this CA is reachable, or
     * `undefined` if no CDP extension should be emitted on issued certs.
     */
    public get crlDistributionUrl(): string | undefined {
        return this._crlDistributionUrl;
    }

    /**
     * Public URL of the OCSP responder, or `undefined` if no AIA OCSP
     * leg should be emitted on issued certs.
     */
    public get ocspResponderUrl(): string | undefined {
        return this._ocspResponderUrl;
    }

    /**
     * Public URL where the issuer's certificate can be fetched, or
     * `undefined` if no AIA caIssuers leg should be emitted.
     */
    public get caIssuersUrl(): string | undefined {
        return this._caIssuersUrl;
    }

    /**
     * Configure the URL embedded as `crlDistributionPoints` in every
     * subsequently-issued certificate. Pass `undefined` to disable
     * the extension entirely. Validated synchronously — throws on
     * empty string, non-http(s) protocol, missing path. Warns (does
     * not throw) when the URL points at loopback.
     *
     * @see US-202
     */
    public setCrlDistributionUrl(url: string | undefined): void {
        this._crlDistributionUrl = validateRevocationUrl(url, "crlDistributionUrl");
    }

    /**
     * Configure the OCSP responder URL embedded as the `OCSP` leg of
     * the `authorityInfoAccess` extension on every subsequently-issued
     * certificate. Pass `undefined` to disable.
     *
     * @see US-202
     */
    public setOcspResponderUrl(url: string | undefined): void {
        this._ocspResponderUrl = validateRevocationUrl(url, "ocspResponderUrl");
    }

    /**
     * Configure the caIssuers URL embedded as the `caIssuers` leg of
     * the `authorityInfoAccess` extension on every subsequently-issued
     * certificate. Pass `undefined` to disable.
     *
     * @see US-202
     */
    public setCaIssuersUrl(url: string | undefined): void {
        this._caIssuersUrl = validateRevocationUrl(url, "caIssuersUrl");
    }

    /** Absolute path to the CA root directory (alias for {@link location}). */
    public get rootDir() {
        return this.location;
    }

    /** Path to the OpenSSL configuration file (`conf/caconfig.cnf`). */
    public get configFile() {
        return path.normalize(path.join(this.rootDir, "./conf/caconfig.cnf"));
    }

    /** Path to the CA private key (`private/cakey.pem`); may be passphrase-encrypted, see {@link getPrivateKey}. */
    public get privateKey() {
        return path.join(path.resolve(this.rootDir), "private/cakey.pem");
    }

    /**
     * The CA private key, decrypted with the configured `privateKeyPassphrase`
     * if it is encrypted. Fails closed (`PrivateKeyPassphraseRequiredError`)
     * on an encrypted key with no or the wrong passphrase.
     */
    public async getPrivateKey(): Promise<PrivateKey> {
        this.#assertKeyIsOnDisk("getPrivateKey");
        return readPrivateKey(this.privateKey, await this._privateKeyPassphrase());
    }

    /**
     * True when this CA signs with an external {@link CaSigner} (HSM/KMS)
     * rather than with `private/cakey.pem`. There is then no private key
     * file on disk, and never was one.
     */
    public get hasExternalSigner(): boolean {
        return this.#signer !== undefined;
    }

    /**
     * Does `cert` certify the key this CA signs with? With the key on disk
     * that is a private-key match; with a signer there is no private key to
     * match, so compare the certified public key against the signer's own -
     * the same question, asked the only way an HSM allows.
     */
    async #certificateMatchesOurKey(certPem: string, certDer: Buffer): Promise<boolean> {
        if (this.#signer) {
            const ours = Buffer.from(await this.#signer.getPublicKey());
            const certified = Buffer.from(new x509.X509Certificate(certPem).publicKey.rawData);
            return ours.equals(certified);
        }
        return certificateMatchesPrivateKey(certDer, await this.getPrivateKey());
    }

    /** Reject the key-file-only operations up front, rather than failing on a missing file later. */
    #assertKeyIsOnDisk(what: string): void {
        if (this.#signer) {
            throw new Error(
                `CertificateAuthority.${what} is not available on a signer-backed CA: ` +
                    "the private key lives in the signer (HSM/KMS) and is never written to disk."
            );
        }
    }

    /**
     * @internal The key every signing operation goes through. An injected
     * {@link CaSigner} is returned as-is; otherwise the on-disk key is read
     * (and decrypted) and handed over as a plain `CryptoKey`. Both are
     * accepted by the `node-opcua-crypto` signing primitives, so callers
     * never branch on which one they got.
     */
    public async _getSigningKey(): Promise<CryptoKey | CaSigner> {
        if (this.#signer) {
            return this.#signer;
        }
        return privateKeyToCryptoKey(await this.getPrivateKey());
    }

    /**
     * Enable, disable, or rotate the passphrase protecting `private/cakey.pem`
     * (temp file + atomic rename, temp file removed on failure). Only
     * rewrites the file: construct a new `CertificateAuthority` with the new
     * passphrase to continue using it.
     */
    public async reencryptPrivateKey(oldPassphrase?: PrivateKeyPassphrase, newPassphrase?: PrivateKeyPassphrase): Promise<void> {
        this.#assertKeyIsOnDisk("reencryptPrivateKey");
        const oldPass = await resolvePrivateKeyPassphrase(oldPassphrase);
        const newPass = await resolvePrivateKeyPassphrase(newPassphrase);
        const key = readPrivateKey(this.privateKey, oldPass);
        await this.#rewritePrivateKeyFile(key, newPass);
    }

    async #rewritePrivateKeyFile(privateKey: PrivateKey, passphrase: string | undefined): Promise<void> {
        const tmpFilename = `${this.privateKey}.${process.pid}-${Date.now()}.tmp`;
        try {
            await writePrivateKeyFile(tmpFilename, privateKey, { passphrase });
            await fs.promises.rename(tmpFilename, this.privateKey);
        } finally {
            await fs.promises.rm(tmpFilename, { force: true });
        }
    }

    /** @internal resolve the configured passphrase, at most once per instance */
    public async _privateKeyPassphrase(): Promise<string | undefined> {
        if (!this.#passphraseResolved) {
            this.#resolvedPassphrase = await resolvePrivateKeyPassphrase(this.#privateKeyPassphrase);
            this.#passphraseResolved = true;
        }
        return this.#resolvedPassphrase;
    }

    /**
     * @internal On an existing key: encrypt it in place if a passphrase is
     * configured and it is still plaintext (secure by default: the option
     * means "protect this key", not "ignore me"), then read it back so a
     * wrong or missing passphrase fails initialize() closed rather than the
     * first signing operation.
     */
    public async _ensurePrivateKeyProtection(): Promise<void> {
        if (this.#signer || !fs.existsSync(this.privateKey)) {
            return;
        }
        if (this.#privateKeyPassphrase !== undefined && !isEncryptedPrivateKeyFile(this.privateKey)) {
            warningLog("CertificateAuthority: private key is plaintext but a passphrase is configured; encrypting it in place");
            const plaintextKey = readPrivateKey(this.privateKey);
            await this.#rewritePrivateKeyFile(plaintextKey, await this._privateKeyPassphrase());
        }
        await this.getPrivateKey();
    }

    /**
     * Acquire a file-based lock on this CA's directory for the duration of
     * `action` — serializes every operation that mutates the certificate
     * database (`index.txt`, `serial`, `crlnumber`, `certs/`,
     * `crl/revocation_list.*`) or the CA's own key/certificate, so
     * concurrent calls on one `CertificateAuthority` (or two instances
     * pointed at the same directory, in this or another process) cannot
     * interleave. Mirrors `CertificateManager.withLock2`.
     *
     * Only ever call this from a top-level public operation — nested calls
     * on the same instance would deadlock, since the underlying file lock
     * is not reentrant.
     *
     * The wait is bounded: a waiter gives up (throws) after
     * `CA_LOCK_MAX_WAIT_MS`. Without a bound, a holder whose openssl child
     * hangs would block every CA operation in every process forever and
     * silently — the lock library's keepalive keeps refreshing the lock
     * file's mtime as long as the holder process is alive, so stale-lock
     * recovery never fires for a live-but-stuck holder. A dead holder's
     * lock goes stale (default 2 minutes) and is taken over well within
     * this bound.
     */
    async #withCaLock<T>(action: () => Promise<T>): Promise<T> {
        const lockFileName = path.join(this.rootDir, ".ca.lock");
        return withLock<T>(
            {
                fileToLock: lockFileName,
                retries: { forever: true, maxRetryTime: CA_LOCK_MAX_WAIT_MS, ...CA_LOCK_RETRY }
            },
            action
        );
    }

    /**
     * @internal Run `action` under this CA's directory lock. For the one
     * legitimate cross-instance use: a subordinate CA's bootstrap signs its
     * certificate with `openssl x509 -CAserial`, which read-increment-writes
     * THIS issuer's `serial` file, and must therefore hold this issuer's
     * lock (ordering is always subordinate -> issuer, so no cycle).
     */
    public async _withCaDirectoryLock<T>(action: () => Promise<T>): Promise<T> {
        return this.#withCaLock(action);
    }

    /** Path to the CA certificate in PEM format (`public/cacert.pem`). */
    public get caCertificate() {
        // the Certificate Authority Certificate
        return makePath(this.rootDir, "./public/cacert.pem");
    }

    /**
     * Path to the issuer certificate chain (`public/issuer_chain.pem`).
     *
     * This file is created by {@link installCACertificate} when the
     * provided cert file contains additional issuer certificates
     * (e.g. intermediate + root). It is appended to signed certs
     * by {@link constructCertificateChain} to produce a full chain
     * per OPC UA Part 6 §6.2.6.
     */
    public get issuerCertificateChain() {
        return makePath(this.rootDir, "./public/issuer_chain.pem");
    }

    /**
     * Path to the current Certificate Revocation List in DER format.
     * (`crl/revocation_list.der`)
     */
    public get revocationListDER() {
        return makePath(this.rootDir, "./crl/revocation_list.der");
    }

    /**
     * Path to the current Certificate Revocation List in PEM format.
     * (`crl/revocation_list.crl`)
     */
    public get revocationList() {
        return makePath(this.rootDir, "./crl/revocation_list.crl");
    }

    /**
     * Path to the concatenated CA certificate + CRL file.
     * Used by OpenSSL for CRL-based verification.
     */
    public get caCertificateWithCrl() {
        return makePath(this.rootDir, "./public/cacertificate_with_crl.pem");
    }

    // ---------------------------------------------------------------
    // Buffer-based accessors (US-059)
    // ---------------------------------------------------------------

    /**
     * Return the CA certificate as a DER-encoded buffer.
     *
     * @throws if the CA certificate file does not exist
     *   (call {@link initialize} first).
     */
    public getCACertificateDER(): Buffer {
        const pem = readCertificatePEM(this.caCertificate);
        return convertPEMtoDER(pem);
    }

    /**
     * Return the CA certificate as a PEM-encoded string.
     *
     * @throws if the CA certificate file does not exist
     *   (call {@link initialize} first).
     */
    public getCACertificatePEM(): string {
        const raw = readCertificatePEM(this.caCertificate);
        // OpenSSL CA cert files may include a human-readable text
        // dump before the PEM block — strip it.
        const beginMarker = "-----BEGIN CERTIFICATE-----";
        const idx = raw.indexOf(beginMarker);
        if (idx > 0) {
            return raw.substring(idx);
        }
        return raw;
    }

    /**
     * Return the current Certificate Revocation List as a
     * DER-encoded buffer.
     *
     * Returns an empty buffer if no CRL has been generated yet.
     */
    public getCRLDER(): Buffer {
        const crlPath = this.revocationListDER;
        if (!fs.existsSync(crlPath)) {
            return Buffer.alloc(0);
        }
        return fs.readFileSync(crlPath);
    }

    /**
     * Return the current Certificate Revocation List as a
     * PEM-encoded string.
     *
     * Returns an empty string if no CRL has been generated yet.
     */
    public getCRLPEM(): string {
        const crlPath = this.revocationList;
        if (!fs.existsSync(crlPath)) {
            return "";
        }
        const raw = fs.readFileSync(crlPath, "utf-8");
        // OpenSSL CRL files may include a human-readable text
        // dump before the PEM block — strip it.
        const beginMarker = "-----BEGIN X509 CRL-----";
        const idx = raw.indexOf(beginMarker);
        if (idx > 0) {
            return raw.substring(idx);
        }
        return raw;
    }

    // ---------------------------------------------------------------
    // Certificate database API (US-057)
    // ---------------------------------------------------------------

    /**
     * Return a list of all issued certificates recorded in the
     * OpenSSL `index.txt` database.
     *
     * Each entry includes the serial number, subject, status,
     * expiry date, and (for revoked certs) the revocation date.
     */
    public getIssuedCertificates(): IssuedCertificateRecord[] {
        return this.#db.readIndex();
    }

    /**
     * Return the total number of certificates recorded in
     * `index.txt`.
     */
    public getIssuedCertificateCount(): number {
        return this.#db.readIndex().length;
    }

    /**
     * Return the status of a certificate by its serial number.
     *
     * @param serial - hex-encoded serial number (e.g. `"1000"`)
     * @returns `"valid"`, `"revoked"`, `"expired"`, or
     *   `undefined` if not found
     */
    public getCertificateStatus(serial: string): "valid" | "revoked" | "expired" | undefined {
        return this.#db.findBySerial(serial)?.status;
    }

    /**
     * Read a specific issued certificate by serial number and
     * return its content as a DER-encoded buffer.
     *
     * OpenSSL stores signed certificates in the `certs/`
     * directory using the naming convention `<SERIAL>.pem`.
     *
     * @param serial - hex-encoded serial number (e.g. `"1000"`)
     * @returns the DER buffer, or `undefined` if not found
     */
    public getCertificateBySerial(serial: string): Buffer | undefined {
        return this.#db.getCertificateBySerial(serial);
    }

    /**
     * Path to the OpenSSL certificate database file.
     */
    public get indexFile(): string {
        return this.#db.indexFile;
    }

    // ---------------------------------------------------------------
    // Buffer-based CA operations (US-058)
    // ---------------------------------------------------------------

    /**
     * Sign a DER-encoded Certificate Signing Request and return
     * the signed certificate as a DER buffer.
     *
     * This method handles temp-file creation and cleanup
     * internally so that callers can work with in-memory
     * buffers only.
     *
     * The CA can override fields from the CSR by passing
     * `options.dns`, `options.ip`, `options.applicationUri`,
     * `options.startDate`, or `options.subject`.
     *
     * @param csrDer - the CSR as a DER-encoded buffer
     * @param options - signing options and CA overrides
     * @returns the signed certificate as a DER-encoded buffer
     */
    public async signCertificateRequestFromDER(csrDer: Buffer, options?: SignCertificateOptions): Promise<Buffer> {
        const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "pki-sign-"));

        try {
            const csrFile = path.join(tmpDir, "request.csr");
            const certFile = path.join(tmpDir, "certificate.pem");

            // Write CSR as PEM
            const csrPem = toPem(csrDer, "CERTIFICATE REQUEST");
            await fs.promises.writeFile(csrFile, csrPem, "utf-8");

            // Build signing parameters — CA overrides take precedence.
            // validityMs (sub-day capable) overrides validity (days) when
            // both are provided; adjustDate() handles precedence.
            const signingParams: Params = {};
            if (options?.validityMs !== undefined) signingParams.validityMs = options.validityMs;
            else signingParams.validity = options?.validity ?? 365;
            if (options?.startDate) signingParams.startDate = options.startDate;
            if (options?.dns) signingParams.dns = options.dns;
            if (options?.ip) signingParams.ip = options.ip;
            if (options?.applicationUri) signingParams.applicationUri = options.applicationUri;
            if (options?.subject) signingParams.subject = options.subject;

            // Delegate to the existing file-based method
            await this.signCertificateRequest(certFile, csrFile, signingParams);

            // Read the signed certificate and convert to DER
            const certPem = readCertificatePEM(certFile);
            return convertPEMtoDER(certPem);
        } finally {
            await fs.promises.rm(tmpDir, {
                recursive: true,
                force: true
            });
        }
    }

    /**
     * Advertise the validity limits this CA can honor.
     *
     * Consumers (notably the GDS server in [`cert_auth.ts`](https://github.com/sterfive/node-opcua-gds))
     * clamp a requested validity against these bounds before calling
     * {@link signCertificateRequestFromDER}, so a misconfigured
     * `defaultCertValidity` cannot ask the CA for something it cannot
     * produce.
     *
     * Defaults match the OpenSSL-backed implementation:
     * - `minValidityMs = 60_000` (1 minute) — practical floor; the
     *   X.509 spec floor is 1 second but very short certs are rarely
     *   useful and pathological for any real deployment.
     * - `maxValidityMs = 10 * 365 * 86_400_000` (≈ 10 years) — long
     *   enough for root CAs.
     * - `validityGranularityMs = 1_000` (1 second) — RFC 5280 §4.1.2.5
     *   floor on `notBefore` / `notAfter`.
     * - `nativeUnit = "second"` — what `x509Date()` actually encodes.
     *
     * @see US-208 — the consumer-side capability story.
     */
    public getCapabilities(): PkiBackendCapabilities {
        return {
            minValidityMs: 60_000,
            maxValidityMs: 10 * 365 * 86_400_000,
            validityGranularityMs: 1_000,
            nativeUnit: "second"
        };
    }

    /**
     * Generate a new RSA key pair, create an internal CSR, sign it
     * with this CA, and return both the certificate and private key
     * as DER-encoded buffers.
     *
     * The private key is **never stored** by the CA — it exists only
     * in a temporary directory that is cleaned up after the operation.
     *
     * This is used by `StartNewKeyPairRequest` (OPC UA Part 12) for
     * constrained devices that cannot generate their own keys.
     *
     * @param options - key generation and certificate parameters
     * @returns `{ certificateDer, privateKey }` — certificate as DER,
     *   private key as a branded `PrivateKey` buffer
     */
    /**
     * An ephemeral key and a CSR for it, written into `tmpDir`. Both
     * `generateKeyPairAndSign*` methods need exactly this, and neither
     * needs a subprocess for it: the key comes from node's crypto and the
     * request is built and self-signed in process, so no `openssl.cnf` has
     * to be rendered either.
     */
    async #createEphemeralKeyAndCsr(
        tmpDir: string,
        keySize: KeySize,
        options: { applicationUri: string; subject?: SubjectOptions | string; dns?: string[]; ip?: string[] }
    ): Promise<{ privateKeyFile: string; csrFile: string }> {
        const privateKeyFile = path.join(tmpDir, "private_key.pem");
        await generatePrivateKeyFile(privateKeyFile, keySize);

        const { csr } = await createCertificateSigningRequest({
            privateKey: await privateKeyToCryptoKey(readPrivateKey(privateKeyFile)),
            subject: options.subject ? new Subject(options.subject).toString() : undefined,
            applicationUri: options.applicationUri,
            dns: options.dns ?? [],
            ip: options.ip ?? [],
            purpose: CertificatePurpose.ForApplication
        });
        const csrFile = path.join(tmpDir, "request.csr");
        await fs.promises.writeFile(csrFile, csr);
        return { privateKeyFile, csrFile };
    }

    public async generateKeyPairAndSignDER(options: GenerateKeyPairAndSignOptions): Promise<{
        certificateDer: Buffer;
        privateKey: PrivateKey;
    }> {
        const keySize = options.keySize ?? 2048;
        const startDate = options.startDate ?? new Date();
        const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "pki-keygen-"));

        try {
            // 1. Ephemeral key + CSR, both in process
            const { privateKeyFile, csrFile } = await this.#createEphemeralKeyAndCsr(tmpDir, keySize, options);

            // 4. Sign the CSR with this CA — validityMs takes precedence
            // over validity when both are provided (adjustDate handles it).
            const certFile = path.join(tmpDir, "certificate.pem");
            const signingParams: Params = {
                applicationUri: options.applicationUri,
                dns: options.dns,
                ip: options.ip,
                startDate
            };
            if (options.validityMs !== undefined) signingParams.validityMs = options.validityMs;
            else signingParams.validity = options.validity ?? 365;
            await this.signCertificateRequest(certFile, csrFile, signingParams);

            // 5. Read results
            const certPem = readCertificatePEM(certFile);
            const certificateDer = convertPEMtoDER(certPem);
            const privateKey = readPrivateKey(privateKeyFile);

            return { certificateDer, privateKey };
        } finally {
            // 6. Securely clean up — private key is never persisted
            await fs.promises.rm(tmpDir, {
                recursive: true,
                force: true
            });
        }
    }

    /**
     * Generate a new RSA key pair, create an internal CSR, sign it
     * with this CA, and return the result as a PKCS#12 (PFX)
     * buffer bundling the certificate, private key, and CA chain.
     *
     * The private key is **never stored** by the CA — it exists only
     * in a temporary directory that is cleaned up after the operation.
     *
     * @param options - key generation, certificate, and PFX options
     * @returns the PFX as a `Buffer`
     */
    public async generateKeyPairAndSignPFX(options: GenerateKeyPairAndSignPFXOptions): Promise<Buffer> {
        const keySize = options.keySize ?? 2048;
        const startDate = options.startDate ?? new Date();
        const passphrase = options.passphrase ?? "";
        const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "pki-keygen-pfx-"));

        try {
            // 1. Ephemeral key + CSR, both in process
            const { privateKeyFile, csrFile } = await this.#createEphemeralKeyAndCsr(tmpDir, keySize, options);

            // 4. Sign the CSR with this CA — validityMs takes precedence
            // over validity when both are provided (adjustDate handles it).
            const certFile = path.join(tmpDir, "certificate.pem");
            const signingParams: Params = {
                applicationUri: options.applicationUri,
                dns: options.dns,
                ip: options.ip,
                startDate
            };
            if (options.validityMs !== undefined) signingParams.validityMs = options.validityMs;
            else signingParams.validity = options.validity ?? 365;
            await this.signCertificateRequest(certFile, csrFile, signingParams);

            // 5. Bundle into PFX. signCertificateRequest leaves the chain in
            // certFile, so the leading block is the certificate and the rest
            // is already this CA's own - no need to read it back separately.
            const blocks = (await fs.promises.readFile(certFile, "utf-8")).match(
                /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g
            );
            if (!blocks || blocks.length === 0) {
                throw new Error(`generateKeyPairAndSignPFX: no certificate was produced in ${certFile}`);
            }
            return await createPfx({
                certificate: convertPEMtoDER(blocks[0]),
                certificateChain: blocks.slice(1).map(convertPEMtoDER),
                privateKey: readPrivateKey(privateKeyFile),
                password: passphrase
            });
        } finally {
            // 7. Securely clean up — private key is never persisted
            await fs.promises.rm(tmpDir, {
                recursive: true,
                force: true
            });
        }
    }

    /**
     * Revoke a DER-encoded certificate and regenerate the CRL.
     *
     * Extracts the serial number from the certificate, then
     * uses the stored cert file at `certs/<serial>.pem` for
     * revocation — avoiding temp-file PEM format mismatches.
     *
     * @param certDer - the certificate as a DER-encoded buffer
     * @param reason - CRL reason code
     *   (default: `"keyCompromise"`)
     * @throws if the certificate's serial is not found in the CA
     */
    public async revokeCertificateDER(certDer: Buffer, reason?: string): Promise<void> {
        // 1. Extract serial from the DER certificate
        const info = exploreCertificate(certDer);
        // exploreCertificate returns serial as "10:00" (colon-hex)
        // openssl stores cert files as "1000.pem" (plain hex upper)
        const serial = info.tbsCertificate.serialNumber.replace(/:/g, "").toUpperCase();

        // 2. Use the cert file that openssl ca already stored
        const storedCertFile = path.join(this.rootDir, "certs", `${serial}.pem`);
        if (!fs.existsSync(storedCertFile)) {
            throw new Error(`Cannot revoke: no stored certificate found for serial ${serial} at ${storedCertFile}`);
        }

        // 3. Delegate to the existing file-based method
        await this.revokeCertificate(storedCertFile, {
            reason: reason ?? "keyCompromise"
        });
    }

    /**
     * Initialize the CA directory structure, generate the CA
     * private key and self-signed certificate if they do not
     * already exist.
     */
    public async initialize(): Promise<void> {
        // the lock file lives inside rootDir, so rootDir must exist before
        // #withCaLock can even acquire it — on a brand-new CA it doesn't yet
        mkdirRecursiveSync(path.resolve(this.rootDir));
        await this.#withCaLock(() => this.#bootstrap());
    }

    /**
     * @internal Shared (backend-agnostic) part of `initialize()`: directory
     * layout, default database files, the "already initialized" / "partial
     * init" checks, and the openssl config file — then delegates CSR
     * generation, CA-certificate signing, and the initial CRL to
     * {@link CaBackend.bootstrap}. Must be called under {@link #withCaLock}.
     */
    async #bootstrap(): Promise<void> {
        const caRootDir = path.resolve(this.rootDir);

        mkdirRecursiveSync(caRootDir);
        ensurePrivateDirectory(path.join(caRootDir, "private"));
        mkdirRecursiveSync(path.join(caRootDir, "public"));
        mkdirRecursiveSync(path.join(caRootDir, "certs"));
        mkdirRecursiveSync(path.join(caRootDir, "crl"));
        mkdirRecursiveSync(path.join(caRootDir, "conf"));

        const serial = path.join(caRootDir, "serial");
        if (!fs.existsSync(serial)) {
            await fs.promises.writeFile(serial, "1000");
        }
        const crlNumber = path.join(caRootDir, "crlnumber");
        if (!fs.existsSync(crlNumber)) {
            await fs.promises.writeFile(crlNumber, "1000");
        }
        const indexFile = path.join(caRootDir, "index.txt");
        if (!fs.existsSync(indexFile)) {
            await fs.promises.writeFile(indexFile, "");
        }

        // A signer-backed CA has no key file and never will: the key is held
        // by the HSM/KMS, so it always "exists" and is never generated here.
        const signerBacked = this.hasExternalSigner;
        const caKeyExists = signerBacked || fs.existsSync(path.join(caRootDir, "private/cakey.pem"));
        const caCertExists = fs.existsSync(path.join(caRootDir, "public/cacert.pem"));
        if (caKeyExists && caCertExists && !config.forceCA) {
            // CA is fully initialized => do not overwrite
            if (!signerBacked) {
                // repair permissions on installs created before this hardening
                restrictPrivateFilePermissions(path.join(caRootDir, "private/cakey.pem"), 0o600);
                // encrypt a plaintext key in place if a passphrase is configured, and
                // fail closed now if the key cannot be read with the configured one
                await this._ensurePrivateKeyProtection();
            }
            debugLog("CA private key and certificate already exist ... skipping");
            return;
        }
        if (!signerBacked && caKeyExists && !caCertExists) {
            // Partial init: key exists but certificate does not.
            // This can happen when a previous CA creation failed
            // (e.g. OpenSSL 3.5 authorityKeyIdentifier error).
            // Remove the stale key so the CA is rebuilt from scratch.
            debugLog("CA private key exists but cacert.pem is missing — rebuilding CA");
            fs.unlinkSync(path.join(caRootDir, "private/cakey.pem"));
            // Also remove the stale CSR if present
            const staleCsr = path.join(caRootDir, "private/cakey.csr");
            if (fs.existsSync(staleCsr)) {
                fs.unlinkSync(staleCsr);
            }
        }

        displayTitle("Create Certificate Authority (CA)");

        const indexFileAttr = path.join(caRootDir, "index.txt.attr");
        if (!fs.existsSync(indexFileAttr)) {
            await fs.promises.writeFile(indexFileAttr, "unique_subject = no");
        }

        const caConfigFile = this.configFile;
        await fs.promises.writeFile(caConfigFile, renderCaConfig(caRootDir));

        if (!signerBacked) {
            const privateKeyFilename = path.join(caRootDir, "private/cakey.pem");

            displayTitle(`Generate the CA private Key - ${this.keySize}`);
            // The first step is to create your RSA Private Key.
            // This key is a 1025,2048,3072 or 2038 bit RSA key which is encrypted using
            // Triple-DES and stored in a PEM format so that it is readable as ASCII text.
            await generatePrivateKeyFile(privateKeyFilename, this.keySize, { passphrase: await this._privateKeyPassphrase() });
            restrictPrivateFilePermissions(privateKeyFilename, 0o600);
        }

        // Once the private key is generated a Certificate Signing Request can be generated.
        // The CSR is then used in one of two ways. Ideally, the CSR will be sent to a Certificate Authority, such as
        // Thawte or Verisign who will verify the identity of the requestor and issue a signed certificate.
        // The second option is to self-sign the CSR, which will be demonstrated in the next section
        await this.#backend.bootstrap(this);
    }

    /**
     * Initialize the CA directory structure and generate the
     * private key + CSR **without signing**.
     *
     * Use this when the CA certificate will be signed by an
     * external (third-party) root CA.  After receiving the signed
     * certificate, call {@link installCACertificate} to complete
     * the setup.
     *
     * **Idempotent / restart-safe:**
     * - If the CA certificate exists and is valid → `{ status: "ready" }`
     * - If the CA certificate has expired → `{ status: "expired", csrPath, expiryDate }`
     *   (a new CSR is generated, preserving the existing private key)
     * - If key + CSR exist but no cert (restart before install) →
     *   `{ status: "pending", csrPath }` without regenerating
     * - Otherwise → generates key + CSR → `{ status: "created", csrPath }`
     *
     * @returns an {@link InitializeCSRResult} describing the CA state
     */
    public async initializeCSR(): Promise<InitializeCSRResult> {
        const caRootDir = path.resolve(this.rootDir);

        // the lock file lives inside rootDir, so rootDir must exist before
        // #withCaLock can even acquire it — on a brand-new CA it doesn't yet
        mkdirRecursiveSync(caRootDir);
        // Everything below mutates the CA directory (key generation guarded
        // only by an existsSync check, default database files, the openssl
        // config, the CSR) and must run under the same lock initialize()
        // uses, or two concurrent initializeCSR() calls can both pass the
        // key-existence check and overwrite each other's key after one of
        // them has already derived a CSR from it.
        return this.#withCaLock(() => this.#initializeCSRLocked(caRootDir));
    }

    async #initializeCSRLocked(caRootDir: string): Promise<InitializeCSRResult> {
        // Ensure directory structure always exists
        for (const dir of ["public", "certs", "crl", "conf"]) {
            mkdirRecursiveSync(path.join(caRootDir, dir));
        }
        ensurePrivateDirectory(path.join(caRootDir, "private"));

        const caCertFile = this.caCertificate;
        const privateKeyFile = path.join(caRootDir, "private/cakey.pem");
        const csrFile = path.join(caRootDir, "private/cakey.csr");

        // a signer-backed CA holds its key externally: it is always
        // "available" and there is no file to generate, protect or permission
        const keyAvailable = this.hasExternalSigner || fs.existsSync(privateKeyFile);

        // repair permissions on installs created before this hardening,
        // encrypt in place if a passphrase is configured, fail closed if unreadable
        if (!this.hasExternalSigner && fs.existsSync(privateKeyFile)) {
            restrictPrivateFilePermissions(privateKeyFile, 0o600);
            await this._ensurePrivateKeyProtection();
        }

        // ── Case 1: cert already exists ──
        if (fs.existsSync(caCertFile)) {
            // Check if the certificate has expired
            const certDer = convertPEMtoDER(readCertificatePEM(caCertFile));
            const certInfo = exploreCertificate(certDer);
            const notAfter = certInfo.tbsCertificate.validity.notAfter;
            if (notAfter.getTime() < Date.now()) {
                // Certificate has expired — regenerate CSR for renewal
                debugLog("CA certificate has expired — generating renewal CSR");
                await this._generateCSR(caRootDir, privateKeyFile, csrFile);
                return { status: "expired", csrPath: csrFile, expiryDate: notAfter };
            }
            debugLog("CA certificate already exists and is valid — ready");
            return { status: "ready" };
        }

        // ── Case 2: key + CSR exist but no cert → pending state ──
        //    (restart between initializeCSR and installCACertificate)
        if (keyAvailable && fs.existsSync(csrFile)) {
            debugLog("CA key + CSR already exist — pending external signing");
            return { status: "pending", csrPath: csrFile };
        }

        // ── Case 3: fresh setup — generate key + CSR ──
        // Create default files (serial, crlnumber, index.txt)
        const serial = path.join(caRootDir, "serial");
        if (!fs.existsSync(serial)) {
            await fs.promises.writeFile(serial, "1000");
        }
        const crlNumber = path.join(caRootDir, "crlnumber");
        if (!fs.existsSync(crlNumber)) {
            await fs.promises.writeFile(crlNumber, "1000");
        }
        const indexFile = path.join(caRootDir, "index.txt");
        if (!fs.existsSync(indexFile)) {
            await fs.promises.writeFile(indexFile, "");
        }
        const indexFileAttr = path.join(caRootDir, "index.txt.attr");
        if (!fs.existsSync(indexFileAttr)) {
            await fs.promises.writeFile(indexFileAttr, "unique_subject = no");
        }

        // Write OpenSSL config
        const caConfigFile = this.configFile;
        await fs.promises.writeFile(caConfigFile, renderCaConfig(caRootDir));

        // Generate private key
        if (!keyAvailable) {
            await generatePrivateKeyFile(privateKeyFile, this.keySize, { passphrase: await this._privateKeyPassphrase() });
            restrictPrivateFilePermissions(privateKeyFile, 0o600);
        }

        // Generate CSR
        await this._generateCSR(caRootDir, privateKeyFile, csrFile);
        return { status: "created", csrPath: csrFile };
    }

    /**
     * Check whether the CA certificate needs renewal and, if so,
     * generate a new CSR for re-signing by the external root CA.
     *
     * Use this while the CA is running to detect upcoming expiry
     * **before** it actually expires. The existing private key is
     * preserved so previously issued certs remain valid.
     *
     * @param thresholdDays - number of days before expiry at which
     *   to trigger renewal (default: 30)
     * @returns an {@link InitializeCSRResult} — `"expired"` if
     *   renewal is needed, `"ready"` if the cert is still valid
     */
    public async renewCSR(thresholdDays = 30): Promise<InitializeCSRResult> {
        const caRootDir = path.resolve(this.rootDir);
        const caCertFile = this.caCertificate;
        const privateKeyFile = path.join(caRootDir, "private/cakey.pem");
        const csrFile = path.join(caRootDir, "private/cakey.csr");

        if (!fs.existsSync(caCertFile)) {
            // No cert at all — delegate to initializeCSR
            return this.initializeCSR();
        }

        const certDer = convertPEMtoDER(readCertificatePEM(caCertFile));
        const certInfo = exploreCertificate(certDer);
        const notAfter = certInfo.tbsCertificate.validity.notAfter;

        const thresholdMs = thresholdDays * 24 * 60 * 60 * 1000;
        if (notAfter.getTime() - Date.now() < thresholdMs) {
            debugLog(`CA certificate expires within ${thresholdDays} days — generating renewal CSR`);
            await this.#withCaLock(() => this._generateCSR(caRootDir, privateKeyFile, csrFile));
            return { status: "expired", csrPath: csrFile, expiryDate: notAfter };
        }

        return { status: "ready" };
    }

    /**
     * Generate a CSR using the existing private key.
     * Must be called under {@link #withCaLock} — the lock is taken by the
     * public callers (`initializeCSR`, `renewCSR`), not here, so that
     * `initializeCSR` can hold one lock across key generation AND CSR
     * generation without the non-reentrant file lock deadlocking.
     * @internal
     */
    private async _generateCSR(caRootDir: string, privateKeyFile: string, csrFile: string): Promise<void> {
        await this.#backend.generateCaCsr(this, caRootDir, privateKeyFile, csrFile);
    }

    /**
     * Install an externally-signed CA certificate and generate
     * the initial CRL.
     *
     * Call this after {@link initializeCSR} once the external
     * root CA has signed the CSR.
     *
     * **Safety checks:**
     * - Verifies that the certificate's public key matches the
     *   CA private key before installing.
     *
     * @param signedCertFile - path to the PEM-encoded signed
     *   CA certificate (issued by the external root CA)
     * @returns an {@link InstallCACertificateResult} with
     *   `status: "success"` or `status: "error"` and a `reason`
     */
    public async installCACertificate(signedCertFile: string): Promise<InstallCACertificateResult> {
        return this.#withCaLock(async () => {
            const caCertFile = this.caCertificate;

            // Read the full content once — may contain a chain
            const fullPem = await fs.promises.readFile(signedCertFile, "utf8");

            // Split PEM blocks: first cert → cacert.pem, rest → issuer_chain.pem
            const pemBlocks = fullPem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
            if (!pemBlocks || pemBlocks.length === 0) {
                return {
                    status: "error",
                    reason: "no_certificate_found",
                    message: "The provided file does not contain any PEM-encoded certificate."
                };
            }

            // Verify the first certificate really belongs to this CA's key
            const certDer = convertPEMtoDER(pemBlocks[0]);
            if (!(await this.#certificateMatchesOurKey(pemBlocks[0], certDer))) {
                return {
                    status: "error",
                    reason: "certificate_key_mismatch",
                    message:
                        "The provided certificate does not match the CA " +
                        "private key. Ensure the certificate was signed " +
                        "from the CSR generated by initializeCSR()."
                };
            }

            // Write the first cert (the CA cert itself)
            await fs.promises.writeFile(caCertFile, `${pemBlocks[0]}\n`);

            // Write any additional issuer certs to the chain file
            const issuerChainFile = this.issuerCertificateChain;
            if (pemBlocks.length > 1) {
                const issuerPem = `${pemBlocks.slice(1).join("\n")}\n`;
                await fs.promises.writeFile(issuerChainFile, issuerPem);
                debugLog(`Stored ${pemBlocks.length - 1} issuer certificate(s) in issuer_chain.pem`);
            } else {
                // No issuer chain — remove stale file if present
                if (fs.existsSync(issuerChainFile)) {
                    await fs.promises.unlink(issuerChainFile);
                }
            }

            // Generate initial CRL
            await this.#backend.regenerateCrl(this);

            return { status: "success" };
        });
    }

    /**
     * Sign a CSR with CA extensions (`v3_ca`), producing a
     * subordinate CA certificate.
     *
     * Unlike {@link signCertificateRequest} which signs with
     * end-entity extensions (SANs, etc.), this method signs
     * with `basicConstraints = CA:TRUE` and `keyUsage =
     * keyCertSign, cRLSign`.
     *
     * @param certFile - output path for the signed CA cert (PEM)
     * @param csrFile - path to the subordinate CA's CSR
     * @param params - signing parameters
     */
    public async signCACertificateRequest(certFile: string, csrFile: string, params: { validity?: number }): Promise<void> {
        await this.#withCaLock(async () => {
            const validity = params.validity ?? 3650;

            await this.#backend.signSubordinateCsr(this, csrFile, certFile, validity);

            // Append this CA's cert chain to the output so the caller
            // receives a complete chain file ready for installCACertificate.
            // Chain format: [signedSubordinateCert, thisCA, thisCA's issuers...]
            await this.constructCertificateChain(certFile);
        });
    }

    /**
     * Rebuild the combined CA certificate + CRL file.
     *
     * This concatenates the CA certificate with the current
     * revocation list so that OpenSSL can verify certificates
     * with CRL checking enabled.
     */
    public async constructCACertificateWithCRL(): Promise<void> {
        const cacertWithCRL = this.caCertificateWithCrl;

        // note : in order to check if the certificate is revoked,
        // you need to specify -crl_check and have both the CA cert and the (applicable) CRL in your trust store.
        // There are two ways to do that:
        // 1. concatenate cacert.pem and crl.pem into one file and use that for -CAfile.
        // 2. use some linked
        // ( from http://security.stackexchange.com/a/58305/59982)

        if (fs.existsSync(this.revocationList)) {
            await fs.promises.writeFile(
                cacertWithCRL,
                fs.readFileSync(this.caCertificate, "utf8") + fs.readFileSync(this.revocationList, "utf8")
            );
        } else {
            // there is no revocation list yet
            await fs.promises.writeFile(cacertWithCRL, fs.readFileSync(this.caCertificate));
        }
    }

    /**
     * Append the CA certificate to a signed certificate file,
     * creating a PEM certificate chain.
     *
     * @param certificate - path to the certificate file to extend
     */
    public async constructCertificateChain(certificate: Filename): Promise<void> {
        assert(fs.existsSync(certificate));
        assert(fs.existsSync(this.caCertificate));

        debugLog(chalk.yellow("        certificate file :"), chalk.cyan(certificate));

        // Build chain: cert + this CA cert + issuer chain (if available)
        let chain = await fs.promises.readFile(certificate, "utf8");
        chain += await fs.promises.readFile(this.caCertificate, "utf8");

        // Append the issuer certificate chain (e.g. root CA cert)
        // to produce a complete chain per OPC UA Part 6 §6.2.6
        if (fs.existsSync(this.issuerCertificateChain)) {
            chain += await fs.promises.readFile(this.issuerCertificateChain, "utf8");
        }

        await fs.promises.writeFile(certificate, chain);
    }

    /**
     * Create a self-signed certificate using OpenSSL.
     *
     * @param certificateFile - output path for the signed certificate
     * @param privateKey - path to the private key file
     * @param params - certificate parameters (subject, validity, SANs)
     */
    public async createSelfSignedCertificate(certificateFile: Filename, privateKey: Filename, params: Params): Promise<void> {
        assert(typeof privateKey === "string");
        assert(fs.existsSync(privateKey));

        if (!certificateFileExist(certificateFile)) {
            return;
        }

        adjustDate(params);
        adjustApplicationUri(params);
        params.dns = params.dns || [];
        params.ip = params.ip || [];

        await this.#withCaLock(async () => {
            await this.#backend.createSelfSignedCertificate(this, certificateFile, privateKey, params);
        });
    }

    /**
     * Regenerate `crl/revocation_list.{crl,der}` from the current database
     * state, without changing any certificate's status. Normally
     * unnecessary — `revokeCertificate` already regenerates the CRL as
     * part of revoking — but useful to force a refresh (e.g. after
     * switching a CA's `backend` between `"openssl"` and `"native"`).
     */
    public async regenerateCrl(): Promise<void> {
        await this.#withCaLock(async () => {
            await this.#backend.regenerateCrl(this);
        });
    }

    /**
     * Revoke a certificate and regenerate the CRL.
     *
     * @param certificate - path to the certificate file to revoke
     * @param params - revocation parameters
     * @param params.reason - CRL reason code
     *   (default `"keyCompromise"`)
     */
    public async revokeCertificate(certificate: Filename, params: Params): Promise<void> {
        const crlReasons = [
            "unspecified",
            "keyCompromise",
            "CACompromise",
            "affiliationChanged",
            "superseded",
            "cessationOfOperation",
            "certificateHold",
            "removeFromCRL"
        ];

        const reason = params.reason || "keyCompromise";
        assert(crlReasons.indexOf(reason) >= 0);

        displayTitle(`Revoking certificate  ${certificate}`);

        await this.#withCaLock(async () => {
            await this.#backend.revoke(this, certificate, reason);
        });
    }

    /**
     * Sign a Certificate Signing Request (CSR) with this CA.
     *
     * The signed certificate is written to `certificate`, and the
     * CA certificate chain plus CRL are appended to form a
     * complete certificate chain.
     *
     * @param certificate - output path for the signed certificate
     * @param certificateSigningRequestFilename - path to the CSR
     * @param params1 - signing parameters (validity, dates, SANs)
     * @returns the path to the signed certificate
     */
    public async signCertificateRequest(
        certificate: Filename,
        certificateSigningRequestFilename: Filename,
        params1: Params
    ): Promise<Filename> {
        // ask the backend, do not assume: a native CA needs no openssl at all
        await this.#backend.preflight();
        assert(fs.existsSync(certificateSigningRequestFilename));
        if (!certificateFileExist(certificate)) {
            return "";
        }
        adjustDate(params1);
        adjustApplicationUri(params1);

        // note :
        // subjectAltName is not copied across
        //  see https://github.com/openssl/openssl/issues/10458
        const csr = await readCertificateSigningRequest(certificateSigningRequestFilename);
        const csrInfo = exploreCertificateSigningRequest(csr);

        const applicationUri = csrInfo.extensionRequest.subjectAltName.uniformResourceIdentifier
            ? csrInfo.extensionRequest.subjectAltName.uniformResourceIdentifier[0]
            : undefined;
        if (typeof applicationUri !== "string") {
            throw new Error("Cannot find applicationUri in CSR");
        }

        const dns = csrInfo.extensionRequest.subjectAltName.dNSName || [];
        let ip = csrInfo.extensionRequest.subjectAltName.iPAddress || [];
        ip = ip.map(octetStringToIpAddress);

        const sanOverride: Required<ProcessAltNamesParam> = { applicationUri, dns, ip };

        return this.#withCaLock(async () => {
            await this.#backend.signEndEntityCsr(this, certificate, certificateSigningRequestFilename, params1, sanOverride);

            displaySubtitle("- construct CA certificate with CRL");
            await this.constructCACertificateWithCRL();

            // construct certificate chain
            //   concatenate certificate with CA Certificate and revocation list
            displaySubtitle("- construct certificate chain");
            await this.constructCertificateChain(certificate);
            // todo
            displaySubtitle("- verify certificate against the root CA");
            await this.verifyCertificate(certificate);

            return certificate;
        });
    }

    /**
     * Check that `certificate` really was signed by this CA, and throw if it
     * was not.
     *
     * This used to do nothing: `openssl verify` crashes on Windows, so the
     * check was left as a placeholder. It no longer needs a subprocess -
     * `verifyCertificateSignature` does it in pure JS, the same way
     * {@link CertificateManager} already validates a chain - so the check
     * that `signCertificateRequest` always claimed to perform now actually
     * happens on every issuance, whichever backend did the signing.
     *
     * Only the leading certificate is examined: the file may be a chain,
     * and the rest of it is this CA's own certificate and its issuers.
     *
     * @param certificate - path to the certificate (or chain) to verify
     */
    public async verifyCertificate(certificate: Filename): Promise<void> {
        const pem = await fs.promises.readFile(certificate, "utf-8");
        const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
        if (!blocks || blocks.length === 0) {
            throw new Error(`verifyCertificate: ${certificate} contains no PEM-encoded certificate`);
        }
        const caCertificateDer = convertPEMtoDER(readCertificatePEM(this.caCertificate));
        if (!verifyCertificateSignature(convertPEMtoDER(blocks[0]), caCertificateDer)) {
            throw new Error(
                `verifyCertificate: ${certificate} was not signed by this certificate authority (${this.caCertificate})`
            );
        }
    }
}

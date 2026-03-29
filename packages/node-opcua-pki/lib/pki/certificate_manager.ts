// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-pki — CertificateManager
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2026 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2026 - Sterfive.com
// ---------------------------------------------------------------------------------------------------------------------
// This project is licensed under the terms of the MIT license.
// ---------------------------------------------------------------------------------------------------------------------

import { EventEmitter } from "node:events";
import fs from "node:fs";
import path from "node:path";
import { drainPendingLocks, withLock } from "@ster5/global-mutex";
import chalk from "chalk";
import chokidar, { type FSWatcher as ChokidarFSWatcher } from "chokidar";
import {
    type Certificate,
    type CertificateInternals,
    type CertificateRevocationList,
    type CertificateRevocationListInfo,
    type DER,
    exploreCertificate,
    exploreCertificateInfo,
    exploreCertificateRevocationList,
    generatePrivateKeyFile,
    makeSHA1Thumbprint,
    readCertificateChain,
    readCertificateChainAsync,
    readCertificateRevocationList,
    split_der,
    toPem,
    verifyCertificateSignature
} from "node-opcua-crypto";

import type { SubjectOptions } from "../misc/subject";
import type {
    CertificateStatus,
    CreateSelfSignCertificateParam,
    CreateSelfSignCertificateWithConfigParam,
    Filename,
    KeySize,
    Thumbprint
} from "../toolbox/common";
import { makePath, mkdirRecursiveSync } from "../toolbox/common2";
import { debugLog, warningLog } from "../toolbox/debug";
import { createCertificateSigningRequestAsync, createSelfSignedCertificate } from "../toolbox/without_openssl";

import _simple_config_template from "./templates/simple_config_template.cnf";

/**
 *
 * a minimalist config file for openssl that allows
 * self-signed certificate to be generated.
 *
 */
const configurationFileSimpleTemplate: string = _simple_config_template;
const fsWriteFile = fs.promises.writeFile;

interface Entry {
    certificate: Certificate;
    filename: string;
    /** Lazily cached result of `exploreCertificate(certificate)`. */
    info?: CertificateInternals;
}

/** Return the cached `info` or compute and cache it. */
function getOrComputeInfo(entry: Entry): CertificateInternals {
    if (!entry.info) {
        entry.info = exploreCertificate(entry.certificate);
    }
    return entry.info;
}

interface CRLEntry {
    crlInfo: CertificateRevocationListInfo;
    filename: string;
}
interface CRLData {
    serialNumbers: { [key: string]: Date };
    crls: CRLEntry[];
}
interface Thumbs {
    trusted: Map<string, Entry>;
    rejected: Map<string, Entry>;
    issuers: {
        certs: Map<string, Entry>;
    };
    /** key = subjectFingerPrint of issuer certificate */
    crl: Map<string, CRLData>;
    /** key = subjectFingerPrint of issuer certificate */
    issuersCrl: Map<string, CRLData>;
}

/**
 * Identifies which PKI sub-store a certificate event originated from.
 */
export type CertificateStore = "trusted" | "rejected" | "issuersCerts";

/**
 * Identifies which PKI sub-store a CRL event originated from.
 */
export type CrlStore = "crl" | "issuersCrl";

/**
 * Events emitted by {@link CertificateManager} when the
 * file-system watchers detect certificate or CRL changes.
 */
export interface CertificateManagerEvents {
    /** A certificate file was added to a store. */
    certificateAdded: (event: { store: CertificateStore; certificate: Certificate; fingerprint: string; filename: string }) => void;
    /** A certificate file was removed from a store. */
    certificateRemoved: (event: { store: CertificateStore; fingerprint: string; filename: string }) => void;
    /** A certificate file was modified in a store. */
    certificateChange: (event: {
        store: CertificateStore;
        certificate: Certificate;
        fingerprint: string;
        filename: string;
    }) => void;
    /** A CRL file was added. */
    crlAdded: (event: { store: CrlStore; filename: string }) => void;
    /** A CRL file was removed. */
    crlRemoved: (event: { store: CrlStore; filename: string }) => void;
}

/**
 * Options controlling certificate validation in
 * {@link CertificateManager.addTrustedCertificateFromChain}.
 *
 * By default all checks are **strict** (secure). Set individual
 * flags to `true` only in test/development environments.
 */
export interface AddCertificateValidationOptions {
    /**
     * Accept certificates whose validity period has expired
     * or is not yet active.
     * @defaultValue false
     */
    acceptExpiredCertificate?: boolean;

    /**
     * Accept certificates that have been revoked by their
     * issuer's CRL.  When `false` (the default), a revoked
     * certificate is rejected with `BadCertificateRevoked`.
     * @defaultValue false
     */
    acceptRevokedCertificate?: boolean;

    /**
     * Do not fail when a CRL is missing for an issuer in the
     * chain.  When `false` (the default), a missing CRL causes
     * `BadCertificateRevocationUnknown`.
     * @defaultValue false
     */
    ignoreMissingRevocationList?: boolean;

    /**
     * Maximum depth of the certificate chain (leaf + issuers).
     * The leaf certificate counts as depth 1.
     * @defaultValue 5
     */
    maxChainLength?: number;
}

/**
 * Options for creating a {@link CertificateManager}.
 */
export interface CertificateManagerOptions {
    /**
     * RSA key size for generated private keys.
     * @defaultValue 2048
     */
    keySize?: KeySize;
    /** Filesystem path where the PKI directory structure is stored. */
    location: string;

    /**
     * Validation options applied by
     * {@link CertificateManager.addTrustedCertificateFromChain}.
     *
     * Defaults are secure — all checks enabled.
     */
    addCertificateValidationOptions?: AddCertificateValidationOptions;
}

/**
 * Parameters for {@link createSelfSignedCertificate}.
 * All fields from {@link CreateSelfSignCertificateParam} are required.
 */
export interface CreateSelfSignCertificateParam1 extends CreateSelfSignCertificateParam {
    /**
     * Output path for the certificate.
     * @defaultValue `"own/certs/self_signed_certificate.pem"`
     */
    outputFile?: Filename;
    /** X.500 subject for the certificate. */
    subject: SubjectOptions | string;
    /** OPC UA application URI for the SAN extension. */
    applicationUri: string;
    /** DNS host names to include in the SAN extension. */
    dns: string[];
    /** Certificate "Not Before" date. */
    startDate: Date;
    /** Number of days the certificate is valid. */
    validity: number;
}

/**
 * Options to fine-tune certificate verification behaviour.
 * Passed to {@link CertificateManager.verifyCertificate}.
 *
 * Without any options, `verifyCertificate` is **strict**: only
 * certificates that are explicitly present in the trusted store
 * will return {@link VerificationStatus.Good}. Unknown or
 * rejected certificates return
 * {@link VerificationStatus.BadCertificateUntrusted} even when
 * their issuer chain is valid.
 *
 * Set {@link acceptCertificateWithValidIssuerChain} to `true`
 * to accept certificates whose issuer chain validates against
 * a trusted CA — even if the leaf certificate itself is not
 * in the trusted store.
 */
export interface VerifyCertificateOptions {
    /** Accept certificates whose "Not After" date has passed. */
    acceptOutdatedCertificate?: boolean;
    /** Accept issuer certificates whose "Not After" date has passed. */
    acceptOutDatedIssuerCertificate?: boolean;
    /** Do not fail when a CRL is missing for an issuer. */
    ignoreMissingRevocationList?: boolean;
    /** Accept certificates whose "Not Before" date is in the future. */
    acceptPendingCertificate?: boolean;
    /**
     * Accept a certificate that is not in the trusted store when
     * its issuer (CA) certificate is trusted, the signature is
     * valid, and the certificate does not appear in the CRL.
     *
     * When `false` (the default), only certificates explicitly
     * placed in the trusted store are accepted — this is the
     * same behaviour as {@link CertificateManager.isCertificateTrusted}.
     *
     * @defaultValue false
     */
    acceptCertificateWithValidIssuerChain?: boolean;
}

/**
 * OPC UA certificate verification status codes.
 *
 * These mirror the OPC UA `StatusCode` values for certificate
 * validation results.
 */
export enum VerificationStatus {
    /** The certificate provided as a parameter is not valid. */
    BadCertificateInvalid = "BadCertificateInvalid",
    /** An error occurred verifying security. */
    BadSecurityChecksFailed = "BadSecurityChecksFailed",
    /** The certificate does not meet the requirements of the security policy. */
    BadCertificatePolicyCheckFailed = "BadCertificatePolicyCheckFailed",
    /** The certificate has expired or is not yet valid. */
    BadCertificateTimeInvalid = "BadCertificateTimeInvalid",
    /** An issuer certificate has expired or is not yet valid. */
    BadCertificateIssuerTimeInvalid = "BadCertificateIssuerTimeInvalid",
    /** The HostName used to connect to a server does not match a HostName in the certificate. */
    BadCertificateHostNameInvalid = "BadCertificateHostNameInvalid",
    /** The URI specified in the ApplicationDescription does not match the URI in the certificate. */
    BadCertificateUriInvalid = "BadCertificateUriInvalid",
    /** The certificate may not be used for the requested operation. */
    BadCertificateUseNotAllowed = "BadCertificateUseNotAllowed",
    /** The issuer certificate may not be used for the requested operation. */
    BadCertificateIssuerUseNotAllowed = "BadCertificateIssuerUseNotAllowed",
    /** The certificate is not trusted. */
    BadCertificateUntrusted = "BadCertificateUntrusted",
    /** It was not possible to determine if the certificate has been revoked. */
    BadCertificateRevocationUnknown = "BadCertificateRevocationUnknown",
    /** It was not possible to determine if the issuer certificate has been revoked. */
    BadCertificateIssuerRevocationUnknown = "BadCertificateIssuerRevocationUnknown",
    /** The certificate has been revoked. */
    BadCertificateRevoked = "BadCertificateRevoked",
    /** The issuer certificate has been revoked. */
    BadCertificateIssuerRevoked = "BadCertificateIssuerRevoked",
    /** The certificate chain is incomplete. */
    BadCertificateChainIncomplete = "BadCertificateChainIncomplete",

    /** Validation OK. */
    Good = "Good"
}

function makeFingerprint(certificate: Certificate | Certificate[] | CertificateRevocationList): string {
    // When the buffer contains a certificate chain (multiple
    // concatenated DER structures), the thumbprint must be
    // computed on the leaf certificate only (first element).
    const chain = Array.isArray(certificate) ? certificate : split_der(certificate);
    return makeSHA1Thumbprint(chain[0]).toString("hex");
}
function short(stringToShorten: string) {
    return stringToShorten.substring(0, 10);
}
// biome-ignore lint/suspicious/noControlCharactersInRegex: we need to filter control characters
const forbiddenChars = /[\x00-\x1F<>:"/\\|?*]/g;
function buildIdealCertificateName(certificate: Certificate): string {
    const fingerprint = makeFingerprint(certificate);
    try {
        const commonName = exploreCertificate(certificate).tbsCertificate.subject.commonName || "";
        // commonName may contain invalid characters for a filename such as / or \ or :
        // that we need to replace with a valid character.
        // replace / or \ or : with _
        const sanitizedCommonName = commonName.replace(forbiddenChars, "_");
        return `${sanitizedCommonName}[${fingerprint}]`;
    } catch (_err) {
        // make be certificate is incorrect !
        return `invalid_certificate_[${fingerprint}]`;
    }
}
function findMatchingIssuerKey(entries: Entry[], wantedIssuerKey: string): Entry[] {
    return entries.filter((entry) => {
        const info = getOrComputeInfo(entry);
        return info.tbsCertificate.extensions && info.tbsCertificate.extensions.subjectKeyIdentifier === wantedIssuerKey;
    });
}

function isSelfSigned2(info: CertificateInternals): boolean {
    return (
        info.tbsCertificate.extensions?.subjectKeyIdentifier ===
        info.tbsCertificate.extensions?.authorityKeyIdentifier?.keyIdentifier
    );
}

function isSelfSigned3(certificate: Buffer): boolean {
    const info = exploreCertificate(certificate);
    return isSelfSigned2(info);
}

function _isIssuerInfo(info: CertificateInternals): boolean {
    const basicConstraints = info.tbsCertificate.extensions?.basicConstraints;
    if (basicConstraints?.cA) {
        return true;
    }
    const keyUsage = info.tbsCertificate.extensions?.keyUsage;
    if (keyUsage?.keyCertSign) {
        return true;
    }
    return false;
}

/**
 * Check if the provided certificate acts as an issuer (CA)
 * @param certificate - the DER-encoded certificate
 * @returns true if the certificate has CA basicConstraints or keyCertSign keyUsage
 */
export function isIssuer(certificate: Certificate): boolean {
    try {
        const info = exploreCertificate(certificate);
        return _isIssuerInfo(info);
    } catch (_err) {
        return false;
    }
}

/**
 * Check if the provided certificate acts as an intermediate issuer.
 * An intermediate issuer is a CA certificate that is not a root CA (not self-signed).
 * @param certificate - the DER-encoded certificate
 * @returns true if the certificate is a CA and is not self-signed
 */
export function isIntermediateIssuer(certificate: Certificate): boolean {
    try {
        const info = exploreCertificate(certificate);
        if (!_isIssuerInfo(info)) {
            return false;
        }
        // A root CA is self-signed. If it's not self-signed, it's an intermediate CA.
        return !isSelfSigned2(info);
    } catch (_err) {
        return false;
    }
}

/**
 * Check if the provided certificate acts as a root issuer.
 * A root issuer is a CA certificate that is self-signed.
 * @param certificate - the DER-encoded certificate
 * @returns true if the certificate is a CA and is self-signed
 */
export function isRootIssuer(certificate: Certificate): boolean {
    try {
        const info = exploreCertificate(certificate);
        if (!_isIssuerInfo(info)) {
            return false;
        }
        // A root CA is securely self-signed
        return isSelfSigned2(info);
    } catch (_err) {
        return false;
    }
}

/**
 * Find the issuer certificate for a given certificate within
 * a provided certificate chain.
 *
 * @param certificate - the DER-encoded certificate whose issuer to find
 * @param chain - candidate issuer certificates to search
 * @returns the matching issuer certificate, or `null` if not found
 */
export function findIssuerCertificateInChain(certificate: Certificate | Certificate[], chain: Certificate[]): Certificate | null {
    const firstCertificate = Array.isArray(certificate) ? certificate[0] : certificate;
    if (!firstCertificate) {
        return null;
    }
    const certInfo = exploreCertificate(firstCertificate);

    // istanbul ignore next
    if (isSelfSigned2(certInfo)) {
        // the certificate is self signed so is it's own issuer.
        return firstCertificate;
    }
    const wantedIssuerKey = certInfo.tbsCertificate.extensions?.authorityKeyIdentifier?.keyIdentifier;

    // istanbul ignore next
    if (!wantedIssuerKey) {
        // Certificate has no extension 3 ! the certificate might have been generated by an old system
        debugLog("Certificate has no extension 3");
        return null;
    }
    const potentialIssuers = chain.filter((c) => {
        const info = exploreCertificate(c);
        return info.tbsCertificate.extensions && info.tbsCertificate.extensions.subjectKeyIdentifier === wantedIssuerKey;
    });

    if (potentialIssuers.length === 1) {
        return potentialIssuers[0];
    }
    if (potentialIssuers.length > 1) {
        debugLog("findIssuerCertificateInChain: certificate is not self-signed but has several issuers");
        return potentialIssuers[0];
    }
    return null;
}

/**
 * Lifecycle state of a {@link CertificateManager} instance.
 */
export enum CertificateManagerState {
    Uninitialized = 0,
    Initializing = 1,
    Initialized = 2,
    Disposing = 3,
    Disposed = 4
}
/**
 * Manages a GDS-compliant PKI directory structure for an OPC UA
 * application.
 *
 * The PKI store layout follows the OPC UA specification:
 *
 * ```
 * <location>/
 *   ├── own/
 *   │   ├── certs/        Own certificate(s)
 *   │   └── private/      Own private key
 *   ├── trusted/
 *   │   ├── certs/        Trusted peer certificates
 *   │   └── crl/          CRLs for trusted certs
 *   ├── rejected/         Untrusted / rejected certificates
 *   └── issuers/
 *       ├── certs/        CA (issuer) certificates
 *       └── crl/          CRLs for issuer certificates
 * ```
 *
 * File-system watchers keep the in-memory indexes in sync with
 * on-disk changes. Call {@link dispose} when the instance is no
 * longer needed to release watchers and allow the process to
 * exit cleanly.
 *
 * ## Environment Variables
 *
 * - **`OPCUA_PKI_USE_POLLING`** — set to `"true"` to use
 *   polling-based file watching instead of native OS events.
 *   Useful for NFS, CIFS, Docker volumes, or other remote /
 *   virtual file systems where native events are unreliable.
 *
 * - **`OPCUA_PKI_POLLING_INTERVAL`** — polling interval in
 *   milliseconds (only effective when polling is enabled).
 *   Clamped to the range [100, 600 000]. Defaults to
 *   {@link folderPollingInterval} (5 000 ms).
 *
 * @example
 * ```ts
 * const cm = new CertificateManager({ location: "/var/pki" });
 * await cm.initialize();
 * const status = await cm.verifyCertificate(cert);
 * await cm.dispose();
 * ```
 */
export class CertificateManager extends EventEmitter {
    // ── Global instance registry ─────────────────────────────────
    // Tracks all initialized CertificateManager instances so their
    // file watchers can be closed automatically on process exit,
    // even if the consumer forgets to call dispose().
    static #activeInstances = new Set<CertificateManager>();
    static #cleanupInstalled = false;

    static #installProcessCleanup(): void {
        if (CertificateManager.#cleanupInstalled) return;
        CertificateManager.#cleanupInstalled = true;

        const closeDanglingWatchers = () => {
            for (const cm of CertificateManager.#activeInstances) {
                for (const w of cm.#watchers) {
                    try {
                        w.close();
                    } catch {
                        /* best-effort */
                    }
                }
                cm.#watchers.splice(0);
                cm.state = CertificateManagerState.Disposed;
            }
            CertificateManager.#activeInstances.clear();
        };

        // beforeExit fires when the event loop has no more work.
        // If persistent:false works correctly on watchers, they
        // won't prevent this event from firing.
        process.on("beforeExit", closeDanglingWatchers);

        // Also handle external termination signals so watchers
        // are cleaned up before the process exits.
        for (const signal of ["SIGINT", "SIGTERM"] as const) {
            process.once(signal, () => {
                closeDanglingWatchers();
                process.exit();
            });
        }
    }

    /**
     * Dispose **all** active CertificateManager instances,
     * closing their file watchers and freeing resources.
     *
     * This is mainly useful in test tear-down to ensure the
     * Node.js process can exit cleanly.
     */
    public static async disposeAll(): Promise<void> {
        const instances = [...CertificateManager.#activeInstances];
        await Promise.all(instances.map((cm) => CertificateManager.prototype.dispose.call(cm)));
    }

    /**
     * Assert that all CertificateManager instances have been
     * properly disposed. Throws an Error listing the locations
     * of any leaked instances.
     *
     * Intended for use in test `afterAll()` / `afterEach()`
     * hooks to catch missing `dispose()` calls early.
     *
     * @example
     * ```ts
     * after(() => {
     *     CertificateManager.checkAllDisposed();
     * });
     * ```
     */
    public static checkAllDisposed(): void {
        if (CertificateManager.#activeInstances.size === 0) return;
        const locations = [...CertificateManager.#activeInstances].map((cm) => cm.rootDir);
        throw new Error(
            `${CertificateManager.#activeInstances.size} CertificateManager instance(s) not disposed:\n  - ${locations.join("\n  - ")}`
        );
    }
    // ─────────────────────────────────────────────────────────────

    /**
     * When `true` (the default), any certificate that is not
     * already in the trusted or rejected store is automatically
     * written to the rejected folder the first time it is seen.
     */
    public untrustUnknownCertificate = true;
    /** Current lifecycle state of this instance. */
    public state: CertificateManagerState = CertificateManagerState.Uninitialized;
    /** @deprecated Use {@link folderPollingInterval} instead (typo fix). */
    public folderPoolingInterval = 5000;

    /** Interval in milliseconds for file-system polling (when enabled). */
    public get folderPollingInterval(): number {
        return this.folderPoolingInterval;
    }
    public set folderPollingInterval(value: number) {
        this.folderPoolingInterval = value;
    }

    /** RSA key size used when generating the private key. */
    public readonly keySize: KeySize;
    readonly #location: string;
    readonly #watchers: fs.FSWatcher[] = [];
    readonly #pendingUnrefs: Set<() => void> = new Set();
    #readCertificatesCalled = false;
    readonly #filenameToHash = new Map<string, string>();
    #initializingPromise?: Promise<void>;
    readonly #addCertValidation: Required<AddCertificateValidationOptions>;

    readonly #thumbs: Thumbs = {
        rejected: new Map(),
        trusted: new Map(),
        issuers: {
            certs: new Map()
        },
        crl: new Map(),
        issuersCrl: new Map()
    };

    /**
     * Create a new CertificateManager.
     *
     * The constructor creates the root directory if it does not
     * exist but does **not** initialise the PKI store — call
     * {@link initialize} before using any other method.
     *
     * @param options - configuration options
     */
    constructor(options: CertificateManagerOptions) {
        super();
        options.keySize = options.keySize || 2048;
        if (!options.location) {
            throw new Error("CertificateManager: missing 'location' option");
        }

        this.#location = makePath(options.location, "");
        this.keySize = options.keySize;

        const v = options.addCertificateValidationOptions ?? {};
        this.#addCertValidation = {
            acceptExpiredCertificate: v.acceptExpiredCertificate ?? false,
            acceptRevokedCertificate: v.acceptRevokedCertificate ?? false,
            ignoreMissingRevocationList: v.ignoreMissingRevocationList ?? false,
            maxChainLength: v.maxChainLength ?? 5
        };

        mkdirRecursiveSync(options.location);

        if (!fs.existsSync(this.#location)) {
            throw new Error(`CertificateManager cannot access location ${this.#location}`);
        }
    }

    /** Path to the OpenSSL configuration file. */
    get configFile() {
        return path.join(this.rootDir, "own/openssl.cnf");
    }

    /** Root directory of the PKI store. */
    get rootDir() {
        return this.#location;
    }

    /** Path to the private key file (`own/private/private_key.pem`). */
    get privateKey() {
        return path.join(this.rootDir, "own/private/private_key.pem");
    }

    /** Path to the OpenSSL random seed file. */
    get randomFile() {
        return path.join(this.rootDir, "./random.rnd");
    }

    /**
     * Move a certificate to the rejected store.
     * If the certificate was previously trusted, it will be removed from the trusted folder.
     * @param certificate - the DER-encoded certificate
     */
    public async rejectCertificate(certificate: Certificate): Promise<void> {
        await this.#moveCertificate(certificate, "rejected");
    }

    /**
     * Move a certificate to the trusted store.
     * If the certificate was previously rejected, it will be removed from the rejected folder.
     * @param certificate - the DER-encoded certificate
     */
    public async trustCertificate(certificate: Certificate): Promise<void> {
        await this.#moveCertificate(certificate, "trusted");
    }

    /**
     * Check whether the trusted certificate store is empty.
     *
     * This inspects the in-memory index, which is kept in
     * sync with the `trusted/certs/` folder by file-system
     * watchers after {@link initialize} has been called.
     */
    public isTrustListEmpty(): boolean {
        return this.#thumbs.trusted.size === 0;
    }

    /**
     * Return the number of certificates currently in the
     * trusted store.
     */
    public getTrustedCertificateCount(): number {
        return this.#thumbs.trusted.size;
    }

    /** Path to the rejected certificates folder. */
    public get rejectedFolder(): string {
        return path.join(this.rootDir, "rejected");
    }
    /** Path to the trusted certificates folder. */
    public get trustedFolder(): string {
        return path.join(this.rootDir, "trusted/certs");
    }
    /** Path to the trusted CRL folder. */
    public get crlFolder(): string {
        return path.join(this.rootDir, "trusted/crl");
    }
    /** Path to the issuer (CA) certificates folder. */
    public get issuersCertFolder(): string {
        return path.join(this.rootDir, "issuers/certs");
    }
    /** Path to the issuer CRL folder. */
    public get issuersCrlFolder(): string {
        return path.join(this.rootDir, "issuers/crl");
    }
    /** Path to the own certificate folder. */
    public get ownCertFolder(): string {
        return path.join(this.rootDir, "own/certs");
    }
    public get ownPrivateFolder(): string {
        return path.join(this.rootDir, "own/private");
    }

    /**
     * Check if a certificate is in the trusted store.
     * If the certificate is unknown and `untrustUnknownCertificate` is set,
     * it will be written to the rejected folder.
     * @param certificate - the DER-encoded certificate
     * @returns `"Good"` if trusted, `"BadCertificateUntrusted"` if rejected/unknown,
     *   or `"BadCertificateInvalid"` if the certificate cannot be parsed.
     */
    public async isCertificateTrusted(
        certificate: Certificate
    ): Promise<"Good" | "BadCertificateUntrusted" | "BadCertificateInvalid"> {
        const fingerprint = makeFingerprint(certificate) as Thumbprint;

        if (this.#thumbs.trusted.has(fingerprint)) {
            return "Good";
        }

        if (!this.#thumbs.rejected.has(fingerprint)) {
            if (!this.untrustUnknownCertificate) {
                return "Good";
            }
            // Verify structure before writing — don't persist invalid data
            try {
                exploreCertificateInfo(certificate);
            } catch (_err) {
                return "BadCertificateInvalid";
            }
            const filename = path.join(this.rejectedFolder, `${buildIdealCertificateName(certificate)}.pem`);
            debugLog("certificate has never been seen before and is now rejected (untrusted) ", filename);
            await fsWriteFile(filename, toPem(certificate, "CERTIFICATE"));
            this.#thumbs.rejected.set(fingerprint, { certificate, filename });
        }
        return "BadCertificateUntrusted";
    }
    async #innerVerifyCertificateAsync(
        certificateOrChain: Certificate | Certificate[],
        _isIssuer: boolean,
        level: number,
        options: VerifyCertificateOptions
    ): Promise<VerificationStatus> {
        if (level >= 5) {
            // maximum level of certificate in chain reached !
            return VerificationStatus.BadSecurityChecksFailed;
        }
        const chain = Array.isArray(certificateOrChain) ? certificateOrChain : [certificateOrChain];
        debugLog("NB CERTIFICATE IN CHAIN = ", chain.length);
        const info = exploreCertificate(chain[0]);

        let hasValidIssuer = false;
        let hasTrustedIssuer = false;
        // check if certificate is attached to a issuer
        const hasIssuerKey = info.tbsCertificate.extensions?.authorityKeyIdentifier?.keyIdentifier;
        debugLog("Certificate as an Issuer Key", hasIssuerKey);

        if (hasIssuerKey) {
            const isSelfSigned = isSelfSigned2(info);

            debugLog("Is the Certificate self-signed  ?", isSelfSigned);
            if (!isSelfSigned) {
                debugLog(
                    "Is issuer found in the list of know issuers ?",
                    "\n subjectKeyIdentifier   = ",
                    info.tbsCertificate.extensions?.subjectKeyIdentifier,
                    "\n authorityKeyIdentifier = ",
                    info.tbsCertificate.extensions?.authorityKeyIdentifier?.keyIdentifier
                );
                let issuerCertificate = await this.findIssuerCertificate(chain[0]);
                if (!issuerCertificate) {
                    // the issuer has not been found in the list of trusted certificate
                    // may be the issuer certificate is in the chain itself ?
                    issuerCertificate = findIssuerCertificateInChain(chain[0], chain);
                    if (!issuerCertificate) {
                        debugLog(
                            " the issuer has not been found in the chain itself nor in the issuer.cert list => the chain is incomplete!"
                        );
                        return VerificationStatus.BadCertificateChainIncomplete;
                    }
                    debugLog(" the issuer certificate has been found in the chain itself ! the chain is complete !");
                } else {
                    debugLog(" the issuer certificate has been found in the issuer.cert folder !");
                }
                const issuerStatus = await this.#innerVerifyCertificateAsync(issuerCertificate, true, level + 1, options);
                if (issuerStatus === VerificationStatus.BadCertificateRevocationUnknown) {
                    // the issuer must have a CRL available .... !
                    return VerificationStatus.BadCertificateIssuerRevocationUnknown;
                }
                if (issuerStatus === VerificationStatus.BadCertificateIssuerRevocationUnknown) {
                    // the issuer must have a CRL available .... !
                    return VerificationStatus.BadCertificateIssuerRevocationUnknown;
                }
                if (issuerStatus === VerificationStatus.BadCertificateTimeInvalid) {
                    if (!options?.acceptOutDatedIssuerCertificate) {
                        // the issuer must have valid dates ....
                        return VerificationStatus.BadCertificateIssuerTimeInvalid;
                    }
                }
                if (issuerStatus === VerificationStatus.BadCertificateUntrusted) {
                    debugLog("warning issuerStatus = ", issuerStatus.toString(), "the issuer certificate is not trusted");
                    // return VerificationStatus.BadSecurityChecksFailed;
                }

                if (issuerStatus !== VerificationStatus.Good && issuerStatus !== VerificationStatus.BadCertificateUntrusted) {
                    // if the issuer has other issue => let's drop!
                    return VerificationStatus.BadSecurityChecksFailed;
                }
                // verify that certificate was signed by issuer
                const isCertificateSignatureOK = verifyCertificateSignature(chain[0], issuerCertificate);
                if (!isCertificateSignatureOK) {
                    debugLog(" the certificate was not signed by the issuer as it claim to be ! Danger");
                    return VerificationStatus.BadSecurityChecksFailed;
                }
                hasValidIssuer = true;

                // let detected if our certificate is in the revocation list
                let revokedStatus = await this.isCertificateRevoked(certificateOrChain);
                if (revokedStatus === VerificationStatus.BadCertificateRevocationUnknown) {
                    if (options?.ignoreMissingRevocationList) {
                        // continue as if the certificate was not revoked
                        revokedStatus = VerificationStatus.Good;
                    }
                }
                if (revokedStatus !== VerificationStatus.Good) {
                    // certificate is revoked !!!
                    debugLog("revokedStatus", revokedStatus);
                    return revokedStatus;
                }

                // let check if the issuer is explicitly trusted
                const issuerTrustedStatus = await this.#checkRejectedOrTrusted(issuerCertificate);
                debugLog("issuerTrustedStatus", issuerTrustedStatus);

                if (issuerTrustedStatus === "unknown") {
                    hasTrustedIssuer = false;
                } else if (issuerTrustedStatus === "trusted") {
                    hasTrustedIssuer = true;
                } else if (issuerTrustedStatus === "rejected") {
                    // we should never get there: this should have been detected before !!!
                    return VerificationStatus.BadSecurityChecksFailed;
                }
            } else {
                // verify that certificate was signed by issuer (self in this case)
                const isCertificateSignatureOK = verifyCertificateSignature(chain[0], chain[0]);
                if (!isCertificateSignatureOK) {
                    debugLog("Self-signed Certificate signature is not valid");
                    return VerificationStatus.BadSecurityChecksFailed;
                }
                const revokedStatus = await this.isCertificateRevoked(certificateOrChain);
                debugLog("revokedStatus of self signed certificate:", revokedStatus);
            }
        }

        const status = await this.#checkRejectedOrTrusted(certificateOrChain);
        if (status === "rejected") {
            if (!(options.acceptCertificateWithValidIssuerChain && hasValidIssuer && hasTrustedIssuer)) {
                return VerificationStatus.BadCertificateUntrusted;
            }
        }
        const _c2 = chain[1] ? exploreCertificateInfo(chain[1]) : "non";
        debugLog("chain[1] info=", _c2);

        // Has SoftwareCertificate passed its issue date and has it not expired ?
        // check dates
        const certificateInfo = exploreCertificateInfo(chain[0]);
        const now = new Date();

        let isTimeInvalid = false;
        // check that certificate is active
        if (certificateInfo.notBefore.getTime() > now.getTime()) {
            // certificate is not active yet
            debugLog(
                `${chalk.red("certificate is invalid : certificate is not active yet !")} not before date =${certificateInfo.notBefore}`
            );
            if (!options.acceptPendingCertificate) {
                isTimeInvalid = true;
            }
        }

        //  check that certificate has not expired
        if (certificateInfo.notAfter.getTime() <= now.getTime()) {
            // certificate is obsolete
            debugLog(
                `${chalk.red("certificate is invalid : certificate has expired !")} not after date =${certificateInfo.notAfter}`
            );
            if (!options.acceptOutdatedCertificate) {
                isTimeInvalid = true;
            }
        }
        if (status === "trusted") {
            return isTimeInvalid ? VerificationStatus.BadCertificateTimeInvalid : VerificationStatus.Good;
        }
        // status should be "unknown" or "rejected" (bypassed) at this point
        if (hasIssuerKey) {
            if (!hasTrustedIssuer) {
                return VerificationStatus.BadCertificateUntrusted;
            }
            if (!hasValidIssuer) {
                return VerificationStatus.BadCertificateUntrusted;
            }
            if (!options.acceptCertificateWithValidIssuerChain) {
                // strict mode: the leaf cert is not in the trusted store
                return VerificationStatus.BadCertificateUntrusted;
            }
            return isTimeInvalid ? VerificationStatus.BadCertificateTimeInvalid : VerificationStatus.Good;
        } else {
            return VerificationStatus.BadCertificateUntrusted;
        }
    }

    /**
     * Internal verification hook called by {@link verifyCertificate}.
     *
     * Subclasses can override this to inject additional validation
     * logic (e.g. application-level policy checks) while still
     * delegating to the default chain/CRL/trust verification.
     *
     * @param certificate - the DER-encoded certificate to verify
     * @param options - verification options forwarded from the
     *   public API
     * @returns the verification status code
     */
    protected async verifyCertificateAsync(
        certificate: Certificate | Certificate[],
        options: VerifyCertificateOptions
    ): Promise<VerificationStatus> {
        // When the input is a single buffer, validate that every
        // DER element it contains is a valid certificate.  A buffer
        // with trailing non-certificate data (e.g. a CRL appended
        // after a certificate) must be rejected early.
        if (!Array.isArray(certificate)) {
            try {
                const derElements = split_der(certificate);
                for (const element of derElements) {
                    // exploreCertificateInfo will throw if the DER
                    // element is not a valid X.509 certificate
                    // (e.g. it is a CRL or other ASN.1 structure).
                    exploreCertificateInfo(element);
                }
            } catch (_err) {
                return VerificationStatus.BadCertificateInvalid;
            }
        }
        const status1 = await this.#innerVerifyCertificateAsync(certificate, false, 0, options);
        return status1;
    }

    /**
     * Verify a certificate against the PKI trust store.
     *
     * This performs a full validation including trust status,
     * issuer chain, CRL revocation checks, and time validity.
     *
     * @param certificate - the DER-encoded certificate to verify
     * @param options - optional flags to relax validation rules
     * @returns the verification status code
     */
    public async verifyCertificate(
        certificate: Certificate | Certificate[],
        options?: VerifyCertificateOptions
    ): Promise<VerificationStatus> {
        // Is the  signature on the SoftwareCertificate valid .?
        if (!certificate) {
            // missing certificate
            return VerificationStatus.BadSecurityChecksFailed;
        }
        try {
            const status = await this.verifyCertificateAsync(certificate, options || {});
            return status;
        } catch (error) {
            warningLog(`verifyCertificate error: ${(error as Error).message}`);
            return VerificationStatus.BadCertificateInvalid;
        }
    }

    /**
     * Initialize the PKI directory structure, generate the
     * private key (if missing), and start file-system watchers.
     *
     * This method is idempotent — subsequent calls are no-ops.
     * It must be called before any certificate operations.
     */
    public async initialize(): Promise<void> {
        if (this.state !== CertificateManagerState.Uninitialized) {
            return;
        }
        this.state = CertificateManagerState.Initializing;
        this.#initializingPromise = this.#initialize();
        await this.#initializingPromise;
        this.#initializingPromise = undefined;
        this.state = CertificateManagerState.Initialized;

        // Register for automatic cleanup on process exit
        CertificateManager.#activeInstances.add(this);
        CertificateManager.#installProcessCleanup();
    }
    async #initialize(): Promise<void> {
        this.state = CertificateManagerState.Initializing;
        const pkiDir = this.#location;
        mkdirRecursiveSync(pkiDir);
        mkdirRecursiveSync(path.join(pkiDir, "own"));
        mkdirRecursiveSync(path.join(pkiDir, "own/certs"));
        mkdirRecursiveSync(path.join(pkiDir, "own/private"));
        mkdirRecursiveSync(path.join(pkiDir, "rejected"));
        mkdirRecursiveSync(path.join(pkiDir, "trusted"));
        mkdirRecursiveSync(path.join(pkiDir, "trusted/certs"));
        mkdirRecursiveSync(path.join(pkiDir, "trusted/crl"));

        mkdirRecursiveSync(path.join(pkiDir, "issuers"));
        mkdirRecursiveSync(path.join(pkiDir, "issuers/certs")); // contains Trusted CA certificates
        mkdirRecursiveSync(path.join(pkiDir, "issuers/crl")); // contains CRL of revoked CA certificates

        if (!fs.existsSync(this.configFile) || !fs.existsSync(this.privateKey)) {
            return await this.withLock2(async () => {
                if (this.state === CertificateManagerState.Disposing || this.state === CertificateManagerState.Disposed) {
                    return;
                }

                if (!fs.existsSync(this.configFile)) {
                    fs.writeFileSync(this.configFile, configurationFileSimpleTemplate);
                }
                // note : openssl 1.1.1 has a bug that causes a failure if
                // random file cannot be found. (should be fixed in 1.1.1.a)
                // if this issue become important we may have to consider checking that rndFile exists and recreate
                // it if not . this could be achieved with the command :
                //      "openssl rand -writerand ${this.randomFile}"
                //
                // cf: https://github.com/node-opcua/node-opcua/issues/554

                if (!fs.existsSync(this.privateKey)) {
                    debugLog("generating private key ...");
                    //   setEnv("RANDFILE", this.randomFile);
                    await generatePrivateKeyFile(this.privateKey, this.keySize);
                    await this.#readCertificates();
                } else {
                    // debugLog("   initialize :  private key already exists ... skipping");
                    await this.#readCertificates();
                }
            });
        } else {
            await this.#readCertificates();
        }
    }

    /**
     * Dispose of the CertificateManager, releasing file watchers
     * and other resources. The instance should not be used after
     * calling this method.
     */
    public async dispose(): Promise<void> {
        if (this.state === CertificateManagerState.Disposing) {
            throw new Error("Already disposing");
        }

        if (this.state === CertificateManagerState.Uninitialized) {
            this.state = CertificateManagerState.Disposed;
            return;
        }

        // Wait for initialization to complete before disposing
        if (this.state === CertificateManagerState.Initializing) {
            if (this.#initializingPromise) {
                await this.#initializingPromise;
            }
        }

        try {
            this.state = CertificateManagerState.Disposing;
            // Wait for any in-flight withLock operations (e.g.
            // fire-and-forget trustCertificate calls) to complete
            // so their setInterval timers are properly cleared.
            await drainPendingLocks();
            // Ensure all fs.watch handles are unref'd even if
            // chokidar hasn't reached "ready" yet.
            for (const unreff of this.#pendingUnrefs) {
                unreff();
            }
            this.#pendingUnrefs.clear();
            await Promise.all(this.#watchers.map((w) => w.close()));
            this.#watchers.forEach((w) => {
                w.removeAllListeners();
            });
            this.#watchers.splice(0);
        } finally {
            this.state = CertificateManagerState.Disposed;
            CertificateManager.#activeInstances.delete(this);
        }
    }

    /**
     * Force a full re-scan of all PKI folders, rebuilding
     * the in-memory `_thumbs` index from scratch.
     *
     * Call this after external processes have modified the
     * PKI folders (e.g. via `writeTrustList` or CLI tools)
     * to ensure the CertificateManager sees the latest
     * state without waiting for file-system events.
     */
    public async reloadCertificates(): Promise<void> {
        // Close existing watchers
        await Promise.all(this.#watchers.map((w) => w.close()));
        for (const w of this.#watchers) {
            w.removeAllListeners();
        }
        this.#watchers.splice(0);

        // Clear in-memory indexes
        this.#thumbs.rejected.clear();
        this.#thumbs.trusted.clear();
        this.#thumbs.issuers.certs.clear();
        this.#thumbs.crl.clear();
        this.#thumbs.issuersCrl.clear();
        this.#filenameToHash.clear();

        // Re-scan all folders
        this.#readCertificatesCalled = false;
        await this.#readCertificates();
    }

    protected async withLock2<T>(action: () => Promise<T>): Promise<T> {
        const lockFileName = path.join(this.rootDir, "mutex");
        return withLock<T>({ fileToLock: lockFileName }, async () => {
            return await action();
        });
    }
    /**
     * Create a self-signed certificate for this PKI's private key.
     *
     * The certificate is written to `params.outputFile` or
     * `own/certs/self_signed_certificate.pem` by default.
     *
     * @param params - certificate parameters (subject, SANs,
     *   validity, etc.)
     */
    public async createSelfSignedCertificate(params: CreateSelfSignCertificateParam1): Promise<void> {
        if (typeof params.applicationUri !== "string") {
            throw new Error("createSelfSignedCertificate: expecting applicationUri to be a string");
        }
        if (!fs.existsSync(this.privateKey)) {
            throw new Error(`Cannot find private key ${this.privateKey}`);
        }
        let certificateFilename = path.join(this.rootDir, "own/certs/self_signed_certificate.pem");
        certificateFilename = params.outputFile || certificateFilename;

        const _params = params as unknown as CreateSelfSignCertificateWithConfigParam;
        _params.rootDir = this.rootDir;
        _params.configFile = this.configFile;
        _params.privateKey = this.privateKey;

        _params.subject = params.subject || "CN=FIXME";
        await this.withLock2(async () => {
            await createSelfSignedCertificate(certificateFilename, _params);
        });
    }

    /**
     * Create a Certificate Signing Request (CSR) using this
     * PKI's private key and configuration.
     *
     * The CSR file is written to `own/certs/` with a timestamped
     * filename.
     *
     * @param params - CSR parameters (subject, SANs)
     * @returns the filesystem path to the generated CSR file
     */
    public async createCertificateRequest(params: CreateSelfSignCertificateParam): Promise<Filename> {
        if (!params) {
            throw new Error("params is required");
        }
        const _params = params as CreateSelfSignCertificateWithConfigParam;
        if (Object.prototype.hasOwnProperty.call(_params, "rootDir")) {
            throw new Error("rootDir should not be specified ");
        }
        _params.rootDir = path.resolve(this.rootDir);
        _params.configFile = path.resolve(this.configFile);
        _params.privateKey = path.resolve(this.privateKey);

        return await this.withLock2<string>(async () => {
            // compose a file name for the request
            const now = new Date();
            const today = `${now.toISOString().slice(0, 10)}_${now.getTime()}`;
            const certificateSigningRequestFilename = path.join(this.rootDir, "own/certs", `certificate_${today}.csr`);
            await createCertificateSigningRequestAsync(certificateSigningRequestFilename, _params);
            return certificateSigningRequestFilename;
        });
    }

    /**
     * Add a CA (issuer) certificate to the issuers store.
     * If the certificate is already present, this is a no-op.
     * @param certificate - the DER-encoded CA certificate
     * @param validate - if `true`, verify the certificate before adding
     * @param addInTrustList - if `true`, also add to the trusted store
     * @returns `VerificationStatus.Good` on success
     */
    public async addIssuer(certificate: DER, validate = false, addInTrustList = false): Promise<VerificationStatus> {
        if (validate) {
            const status = await this.verifyCertificate(certificate);
            if (status !== VerificationStatus.Good && status !== VerificationStatus.BadCertificateUntrusted) {
                return status;
            }
        }
        const pemCertificate = toPem(certificate, "CERTIFICATE");
        const fingerprint = makeFingerprint(certificate);
        if (this.#thumbs.issuers.certs.has(fingerprint)) {
            // already in .. simply ignore
            return VerificationStatus.Good;
        }
        // write certificate
        const filename = path.join(this.issuersCertFolder, `issuer_${buildIdealCertificateName(certificate)}.pem`);
        await fs.promises.writeFile(filename, pemCertificate, "ascii");

        // first time seen, let's save it.
        this.#thumbs.issuers.certs.set(fingerprint, { certificate, filename });

        if (addInTrustList) {
            // add certificate in the trust list as well
            await this.trustCertificate(certificate);
        }

        return VerificationStatus.Good;
    }

    /**
     * Add multiple CA (issuer) certificates to the issuers store.
     * @param certificates - the DER-encoded CA certificates
     * @param validate - if `true`, verify each certificate before adding
     * @param addInTrustList - if `true`, also add each certificate to the trusted store
     * @returns `VerificationStatus.Good` on success
     */
    public async addIssuers(certificates: Certificate[], validate = false, addInTrustList = false): Promise<VerificationStatus> {
        for (const certificate of certificates) {
            // check that certificate is a issuer certificate
            if (!isIssuer(certificate)) {
                warningLog(`Certificate ${makeFingerprint(certificate)} is not a issuer certificate`);
                continue;
            }
            await this.addIssuer(certificate, validate, addInTrustList);
        }
        return VerificationStatus.Good;
    }

    /**
     * Add a CRL to the certificate manager.
     * @param crl - the CRL to add
     * @param target - "issuers" (default) writes to issuers/crl, "trusted" writes to trusted/crl
     */
    public async addRevocationList(
        crl: CertificateRevocationList,
        target: "issuers" | "trusted" = "issuers"
    ): Promise<VerificationStatus> {
        return await this.withLock2<VerificationStatus>(async () => {
            try {
                const index = target === "trusted" ? this.#thumbs.crl : this.#thumbs.issuersCrl;
                const folder = target === "trusted" ? this.crlFolder : this.issuersCrlFolder;

                const crlInfo = exploreCertificateRevocationList(crl);
                const key = crlInfo.tbsCertList.issuerFingerprint;
                if (!index.has(key)) {
                    index.set(key, { crls: [], serialNumbers: {} });
                }
                const pemCertificate = toPem(crl, "X509 CRL");
                // Use the issuer fingerprint for the filename — NOT buildIdealCertificateName()
                // which expects a certificate, not a CRL. Passing a CRL causes
                // exploreCertificate() to throw, producing "invalid_certificate_" names.
                const sanitizedKey = key.replace(/:/g, "");
                const filename = path.join(folder, `crl_[${sanitizedKey}].pem`);
                await fs.promises.writeFile(filename, pemCertificate, "ascii");

                await this.#onCrlFileAdded(index, filename);

                await this.#waitAndCheckCRLProcessingStatus();

                return VerificationStatus.Good;
            } catch (err) {
                debugLog(err);
                return VerificationStatus.BadSecurityChecksFailed;
            }
        });
    }

    /**
     * Remove all CRL files from the specified folder(s) and clear the
     * corresponding in-memory index.
     * @param target - "issuers" clears issuers/crl, "trusted" clears
     *   trusted/crl, "all" clears both.
     */
    public async clearRevocationLists(target: "issuers" | "trusted" | "all"): Promise<void> {
        const clearFolder = async (folder: string, index: Map<string, CRLData>) => {
            try {
                const files = await fs.promises.readdir(folder);
                for (const file of files) {
                    const ext = path.extname(file).toLowerCase();
                    if (ext === ".crl" || ext === ".pem" || ext === ".der") {
                        await fs.promises.unlink(path.join(folder, file));
                    }
                }
            } catch (err: unknown) {
                if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
                    throw err;
                }
            }
            index.clear();
        };

        if (target === "issuers" || target === "all") {
            await clearFolder(this.issuersCrlFolder, this.#thumbs.issuersCrl);
        }
        if (target === "trusted" || target === "all") {
            await clearFolder(this.crlFolder, this.#thumbs.crl);
        }
    }

    /**
     * Check whether an issuer certificate with the given thumbprint
     * is already registered.
     * @param thumbprint - hex-encoded SHA-1 thumbprint (lowercase)
     */
    public async hasIssuer(thumbprint: string): Promise<boolean> {
        await this.#readCertificates();
        const normalized = thumbprint.toLowerCase();
        return this.#thumbs.issuers.certs.has(normalized);
    }

    /**
     * Remove a trusted certificate identified by its SHA-1 thumbprint.
     * Deletes the file on disk and removes the entry from the
     * in-memory index.
     * @param thumbprint - hex-encoded SHA-1 thumbprint (lowercase)
     * @returns the removed certificate buffer, or `null` if not found
     */
    public async removeTrustedCertificate(thumbprint: string): Promise<Certificate | null> {
        await this.#readCertificates();
        const normalized = thumbprint.toLowerCase();
        const entry = this.#thumbs.trusted.get(normalized);
        if (!entry) {
            return null;
        }
        try {
            await fs.promises.unlink(entry.filename);
        } catch (err: unknown) {
            if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
                throw err;
            }
        }
        this.#thumbs.trusted.delete(normalized);
        return entry.certificate;
    }

    /**
     * Remove an issuer certificate identified by its SHA-1 thumbprint.
     * Deletes the file on disk and removes the entry from the
     * in-memory index.
     * @param thumbprint - hex-encoded SHA-1 thumbprint (lowercase)
     * @returns the removed certificate buffer, or `null` if not found
     */
    public async removeIssuer(thumbprint: string): Promise<Certificate | null> {
        await this.#readCertificates();
        const normalized = thumbprint.toLowerCase();
        const entry = this.#thumbs.issuers.certs.get(normalized);
        if (!entry) {
            return null;
        }
        try {
            await fs.promises.unlink(entry.filename);
        } catch (err: unknown) {
            if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
                throw err;
            }
        }
        this.#thumbs.issuers.certs.delete(normalized);
        return entry.certificate;
    }

    /**
     * Remove all CRL files that were issued by the given CA certificate
     * from the specified folder (or both).
     * @param issuerCertificate - the CA certificate whose CRLs to remove
     * @param target - "issuers", "trusted", or "all" (default "all")
     */
    public async removeRevocationListsForIssuer(
        issuerCertificate: Certificate,
        target: "issuers" | "trusted" | "all" = "all"
    ): Promise<void> {
        const issuerInfo = exploreCertificate(issuerCertificate);
        const issuerFingerprint = issuerInfo.tbsCertificate.subjectFingerPrint;

        const processIndex = async (index: Map<string, CRLData>) => {
            const crlData = index.get(issuerFingerprint);
            if (!crlData) return;
            for (const crlEntry of crlData.crls) {
                try {
                    await fs.promises.unlink(crlEntry.filename);
                } catch (err: unknown) {
                    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
                        throw err;
                    }
                }
            }
            index.delete(issuerFingerprint);
        };

        if (target === "issuers" || target === "all") {
            await processIndex(this.#thumbs.issuersCrl);
        }
        if (target === "trusted" || target === "all") {
            await processIndex(this.#thumbs.crl);
        }
    }

    /**
     * Validate a certificate (optionally with its chain) and add
     * the leaf certificate to the trusted store.
     *
     * Performs OPC UA Part 4, Table 100 validation:
     *
     * 1. **Certificate Structure** — parse the DER encoding.
     * 2. **Build Certificate Chain** — walk from the leaf to a
     *    self-signed root CA, using the provided chain and the
     *    issuers store.
     * 3. **Signature** — verify each certificate's signature
     *    against its issuer.
     * 4. **Issuer Presence** — every issuer in the chain must
     *    already be registered in the issuers store (per GDS
     *    7.8.2.6).
     * 5. **Validity Period** — each certificate must be within
     *    its validity window (overridable via
     *    {@link AddCertificateValidationOptions.acceptExpiredCertificate}).
     * 6. **Revocation Check** — each certificate is checked
     *    against its issuer's CRL (overridable via
     *    {@link AddCertificateValidationOptions.acceptRevokedCertificate}
     *    and {@link AddCertificateValidationOptions.ignoreMissingRevocationList}).
     *
     * Only the leaf certificate is added to the trusted store.
     *
     * @param certificateChain - DER-encoded certificate or chain
     * @returns `VerificationStatus.Good` on success, or an error
     *  status indicating why the certificate was rejected.
     */
    public async addTrustedCertificateFromChain(certificateChain: Certificate | Certificate[]): Promise<VerificationStatus> {
        // Top-level guard: never let an unexpected error escape.
        // Every code path returns a VerificationStatus; unexpected
        // throws (corrupt buffers, crypto failures, etc.) are
        // caught here and mapped to BadCertificateInvalid.
        try {
            return await this.#addTrustedCertificateFromChainImpl(certificateChain);
        } catch (_err) {
            warningLog("addTrustedCertificateFromChain: unexpected error", _err);
            return VerificationStatus.BadCertificateInvalid;
        }
    }

    async #addTrustedCertificateFromChainImpl(certificateChain: Certificate | Certificate[]): Promise<VerificationStatus> {
        let certificates: Certificate[];
        try {
            certificates = Array.isArray(certificateChain) ? certificateChain : split_der(certificateChain);
        } catch (_err) {
            return VerificationStatus.BadCertificateInvalid;
        }
        if (certificates.length === 0) {
            return VerificationStatus.BadCertificateInvalid;
        }
        const leafCertificate = certificates[0];
        const opts = this.#addCertValidation;

        // ── Step 1: Certificate Structure ────────────────────────
        let leafInfo: CertificateInternals;
        try {
            leafInfo = exploreCertificate(leafCertificate);
        } catch (_err) {
            return VerificationStatus.BadCertificateInvalid;
        }

        // Re-scan the issuers folder to pick up certificates
        // added directly to disk (e.g. by GDS push or external
        // tooling) that the file-system watcher may not have
        // delivered yet.
        await this.#scanCertFolder(this.issuersCertFolder, this.#thumbs.issuers.certs);

        // ── Step 2–6: Walk the chain from leaf to root ───────────
        // depth counts the number of certificates validated in the
        // chain.  maxChainLength=1 → only self-signed certs;
        // maxChainLength=2 → leaf + root CA; etc.
        let currentCert = leafCertificate;
        let currentInfo = leafInfo;
        let depth = 0;

        while (true) {
            depth++;
            if (depth > opts.maxChainLength) {
                // Chain depth exceeded before reaching root
                return VerificationStatus.BadSecurityChecksFailed;
            }

            // ── Step 5: Validity Period ──────────────────────────
            if (!opts.acceptExpiredCertificate) {
                let certDetails: ReturnType<typeof exploreCertificateInfo>;
                try {
                    certDetails = exploreCertificateInfo(currentCert);
                } catch (_err) {
                    return VerificationStatus.BadCertificateInvalid;
                }
                const now = new Date();
                if (certDetails.notBefore.getTime() > now.getTime()) {
                    return VerificationStatus.BadCertificateTimeInvalid;
                }
                if (certDetails.notAfter.getTime() <= now.getTime()) {
                    return depth === 1
                        ? VerificationStatus.BadCertificateTimeInvalid
                        : VerificationStatus.BadCertificateIssuerTimeInvalid;
                }
            }

            // ── Self-signed certificate ──────────────────────────
            if (isSelfSigned2(currentInfo)) {
                // Step 3: Verify self-signature
                try {
                    if (!verifyCertificateSignature(currentCert, currentCert)) {
                        return VerificationStatus.BadCertificateInvalid;
                    }
                } catch (_err) {
                    return VerificationStatus.BadCertificateInvalid;
                }
                // Self-signed certificates don't need revocation
                // or issuer checks — we're at the root.
                break;
            }

            // ── Step 2: Find issuer ──────────────────────────────
            // First try findIssuerCertificate (checks issuers store
            // and trusted store), then fall back to the chain.
            let issuerCert = await this.findIssuerCertificate(currentCert);
            if (!issuerCert) {
                // The issuer is not in the issuers store — try
                // the explicitly provided chain.
                issuerCert = findIssuerCertificateInChain(currentCert, certificates);
                if (!issuerCert || issuerCert === currentCert) {
                    return VerificationStatus.BadCertificateChainIncomplete;
                }
            }

            // ── Step 3: Signature verification ───────────────────
            try {
                if (!verifyCertificateSignature(currentCert, issuerCert)) {
                    return VerificationStatus.BadCertificateInvalid;
                }
            } catch (_err) {
                return VerificationStatus.BadCertificateInvalid;
            }

            // ── Step 4: Issuer must be in the issuers store ──────
            // Per GDS 7.8.2.6: "This Method will return a
            // validation error if the Certificate is issued by a CA
            // and the Certificate for the issuer is not in the
            // TrustList"
            const issuerThumbprint = makeFingerprint(issuerCert);
            if (!(await this.hasIssuer(issuerThumbprint))) {
                return VerificationStatus.BadCertificateChainIncomplete;
            }

            // ── Step 6: Revocation check ─────────────────────────
            const revokedStatus = await this.isCertificateRevoked(currentCert, issuerCert);
            if (revokedStatus === VerificationStatus.BadCertificateRevoked) {
                if (!opts.acceptRevokedCertificate) {
                    return VerificationStatus.BadCertificateRevoked;
                }
            } else if (revokedStatus === VerificationStatus.BadCertificateRevocationUnknown) {
                if (!opts.ignoreMissingRevocationList) {
                    return VerificationStatus.BadCertificateRevocationUnknown;
                }
            }

            // Move up the chain
            currentCert = issuerCert;
            try {
                currentInfo = exploreCertificate(currentCert);
            } catch (_err) {
                return VerificationStatus.BadCertificateInvalid;
            }
        }

        // All checks passed — trust the leaf certificate
        await this.trustCertificate(leafCertificate);
        return VerificationStatus.Good;
    }

    /**
     * Check whether an issuer certificate is still needed by any
     * certificate in the trusted store.
     *
     * This is used before removing an issuer to ensure that
     * doing so would not break the chain of any trusted
     * certificate.
     *
     * @param issuerCertificate - the CA certificate to check
     * @returns `true` if at least one trusted certificate was
     *   signed by this issuer.
     */
    public async isIssuerInUseByTrustedCertificate(issuerCertificate: Certificate): Promise<boolean> {
        await this.#readCertificates();
        for (const entry of this.#thumbs.trusted.values()) {
            if (!entry.certificate) continue;
            try {
                if (verifyCertificateSignature(entry.certificate, issuerCertificate)) {
                    return true;
                }
            } catch (_err) {
                // Skip certificates that can't be verified
            }
        }
        return false;
    }

    /**
     *  find the issuer certificate among the trusted  issuer certificates.
     *
     *  The findIssuerCertificate method is an asynchronous method that attempts to find
     *  the issuer certificate for a given certificate from the list of issuer certificate declared in the PKI
     *
     *  - If the certificate is self-signed, it returns the certificate itself.
     *
     *  - If the certificate has no extension 3, it is assumed to be generated by an old system, and a null value is returned.
     *
     *  - the method checks both issuer and trusted certificates and returns the appropriate issuercertificate,
     *    if found. If multiple matching certificates are found, a warning is logged to the console.
     *
     */
    public async findIssuerCertificate(certificate: Certificate | Certificate[]): Promise<Certificate | null> {
        const firstCertificate = Array.isArray(certificate) ? certificate[0] : certificate;
        const certInfo = exploreCertificate(firstCertificate);

        if (isSelfSigned2(certInfo)) {
            // the certificate is self signed so is it's own issuer.
            return firstCertificate;
        }

        const wantedIssuerKey = certInfo.tbsCertificate.extensions?.authorityKeyIdentifier?.keyIdentifier;

        if (!wantedIssuerKey) {
            // Certificate has no extension 3 ! the certificate might have been generated by an old system
            debugLog("Certificate has no extension 3");
            return null;
        }

        const issuerCertificates = [...this.#thumbs.issuers.certs.values()];

        const selectedIssuerCertificates = findMatchingIssuerKey(issuerCertificates, wantedIssuerKey);

        if (selectedIssuerCertificates.length > 0) {
            if (selectedIssuerCertificates.length > 1) {
                warningLog("Warning more than one issuer certificate exists with subjectKeyIdentifier ", wantedIssuerKey);
            }
            return selectedIssuerCertificates[0].certificate || null;
        }
        // check also in trusted  list
        const trustedCertificates = [...this.#thumbs.trusted.values()];
        const selectedTrustedCertificates = findMatchingIssuerKey(trustedCertificates, wantedIssuerKey);

        if (selectedTrustedCertificates.length > 1) {
            warningLog(
                "Warning more than one certificate exists with subjectKeyIdentifier in trusted certificate list ",
                wantedIssuerKey,
                selectedTrustedCertificates.length
            );
        }
        return selectedTrustedCertificates.length > 0 ? selectedTrustedCertificates[0].certificate : null;
    }

    /**
     *
     * check if the certificate explicitly appear in the trust list, the reject list or none.
     * In case of being in the reject and trusted list at the same time is consider: rejected.
     * @internal
     * @private
     */
    async #checkRejectedOrTrusted(certificate: Certificate | Certificate[]): Promise<CertificateStatus> {
        const firstCertificate = Array.isArray(certificate) ? certificate[0] : certificate;
        const fingerprint = makeFingerprint(firstCertificate);

        debugLog("#checkRejectedOrTrusted fingerprint ", short(fingerprint));

        await this.#readCertificates();

        if (this.#thumbs.rejected.has(fingerprint)) {
            return "rejected";
        }
        if (this.#thumbs.trusted.has(fingerprint)) {
            return "trusted";
        }
        return "unknown";
    }

    async #moveCertificate(certificate: Certificate, newStatus: CertificateStatus) {
        await this.withLock2(async () => {
            const fingerprint = makeFingerprint(certificate);

            let status = await this.#checkRejectedOrTrusted(certificate);
            if (status === "unknown") {
                // # unknown mean rejected
                const pem = toPem(certificate, "CERTIFICATE");
                const filename = path.join(this.rejectedFolder, `${buildIdealCertificateName(certificate)}.pem`);
                await fs.promises.writeFile(filename, pem);
                this.#thumbs.rejected.set(fingerprint, { certificate, filename });
                status = "rejected";
            }

            debugLog("#moveCertificate", fingerprint.substring(0, 10), "from", status, "to", newStatus);

            if (status !== "rejected" && status !== "trusted") {
                throw new Error(`#moveCertificate: unexpected status '${status}' for certificate ${fingerprint.substring(0, 10)}`);
            }

            if (status !== newStatus) {
                const indexSrc = status === "rejected" ? this.#thumbs.rejected : this.#thumbs.trusted;
                const srcEntry = indexSrc.get(fingerprint);

                if (!srcEntry) {
                    debugLog(" cannot find certificate ", fingerprint.substring(0, 10), " in", status);
                    throw new Error(`#moveCertificate: certificate ${fingerprint.substring(0, 10)} not found in ${status} index`);
                }
                const destFolder = newStatus === "trusted" ? this.trustedFolder : this.rejectedFolder;
                const certificateDest = path.join(destFolder, path.basename(srcEntry.filename));

                debugLog("#moveCertificate", fingerprint.substring(0, 10), "old name", srcEntry.filename);
                debugLog("#moveCertificate", fingerprint.substring(0, 10), "new name", certificateDest);
                await fs.promises.rename(srcEntry.filename, certificateDest);
                indexSrc.delete(fingerprint);
                const indexDest = newStatus === "trusted" ? this.#thumbs.trusted : this.#thumbs.rejected;
                indexDest.set(fingerprint, { certificate, filename: certificateDest });
            }
        });
    }
    #findAssociatedCRLs(issuerCertificate: Certificate): CRLData | null {
        const issuerCertificateInfo = exploreCertificate(issuerCertificate);
        const key = issuerCertificateInfo.tbsCertificate.subjectFingerPrint;
        return this.#thumbs.issuersCrl.get(key) ?? this.#thumbs.crl.get(key) ?? null;
    }

    /**
     * Check whether a certificate has been revoked by its issuer's CRL.
     *
     * - Self-signed certificates are never considered revoked.
     * - If no `issuerCertificate` is provided, the method attempts
     *   to find it via {@link findIssuerCertificate}.
     *
     * @param certificate - the DER-encoded certificate to check
     * @param issuerCertificate - optional issuer certificate; looked
     *   up automatically when omitted
     * @returns `Good` if not revoked, `BadCertificateRevoked` if the
     *   serial number appears in a CRL,
     *   `BadCertificateRevocationUnknown` if no CRL is available,
     *   or `BadCertificateChainIncomplete` if the issuer cannot be
     *   found.
     */
    public async isCertificateRevoked(
        certificate: Certificate | Certificate[],
        issuerCertificate?: Certificate | null
    ): Promise<VerificationStatus> {
        const firstCertificate = Array.isArray(certificate) ? certificate[0] : certificate;
        if (isSelfSigned3(firstCertificate)) {
            return VerificationStatus.Good;
        }

        if (!issuerCertificate) {
            issuerCertificate = await this.findIssuerCertificate(firstCertificate);
        }
        if (!issuerCertificate) {
            return VerificationStatus.BadCertificateChainIncomplete;
        }
        const crls = this.#findAssociatedCRLs(issuerCertificate);

        if (!crls) {
            return VerificationStatus.BadCertificateRevocationUnknown;
        }
        const certInfo = exploreCertificate(firstCertificate);
        const serialNumber =
            certInfo.tbsCertificate.serialNumber || certInfo.tbsCertificate.extensions?.authorityKeyIdentifier?.serial || "";

        const key = certInfo.tbsCertificate.extensions?.authorityKeyIdentifier?.authorityCertIssuerFingerPrint || "<unknown>";
        const crl2 = this.#thumbs.crl.get(key) ?? null;

        if (crls.serialNumbers[serialNumber] || crl2?.serialNumbers[serialNumber]) {
            return VerificationStatus.BadCertificateRevoked;
        }
        return VerificationStatus.Good;
    }

    #pendingCrlToProcess = 0;
    #onCrlProcessWaiters: (() => void)[] = [];
    #queue: { index: Map<string, CRLData>; filename: string }[] = [];
    #onCrlFileAdded(index: Map<string, CRLData>, filename: string) {
        this.#queue.push({ index, filename });
        this.#pendingCrlToProcess += 1;
        if (this.#pendingCrlToProcess === 1) {
            this.#processNextCrl();
        }
    }
    async #processNextCrl() {
        try {
            const nextCRL = this.#queue.shift();
            if (!nextCRL) return;
            const { index, filename } = nextCRL;
            const crl = await readCertificateRevocationList(filename);
            const crlInfo = exploreCertificateRevocationList(crl);
            debugLog(chalk.cyan("add CRL in folder "), filename);
            const fingerprint = crlInfo.tbsCertList.issuerFingerprint;
            if (!index.has(fingerprint)) {
                index.set(fingerprint, { crls: [], serialNumbers: {} });
            }
            const data = index.get(fingerprint) || { crls: [], serialNumbers: {} };
            data.crls.push({ crlInfo, filename });

            // now inject serial numbers
            for (const revokedCertificate of crlInfo.tbsCertList.revokedCertificates) {
                const serialNumber = revokedCertificate.userCertificate;
                if (!data.serialNumbers[serialNumber]) {
                    data.serialNumbers[serialNumber] = revokedCertificate.revocationDate;
                }
            }
            debugLog(chalk.cyan("CRL"), fingerprint, "serial numbers = ", Object.keys(data.serialNumbers));
        } catch (err) {
            debugLog("CRL filename error =");
            debugLog(err);
        }
        this.#pendingCrlToProcess -= 1;
        if (this.#pendingCrlToProcess === 0) {
            for (const waiter of this.#onCrlProcessWaiters) {
                waiter();
            }
            this.#onCrlProcessWaiters.length = 0;
        } else {
            this.#processNextCrl();
        }
    }
    async #readCertificates(): Promise<void> {
        if (this.#readCertificatesCalled) {
            return;
        }
        this.#readCertificatesCalled = true;

        // Chokidar configuration choices:
        //
        // usePolling: false (default)
        //   Use native OS file-system events (inotify on Linux,
        //   FSEvents on macOS, ReadDirectoryChangesW on Windows)
        //   for near-real-time detection of cert/CRL additions
        //   and removals. This is significantly faster than
        //   polling (milliseconds vs seconds).
        //
        //   Set OPCUA_PKI_USE_POLLING=true to revert to polling
        //   for environments where native events are unreliable
        //   (NFS, CIFS, Docker volumes, or other remote/virtual
        //   file systems).
        //
        // persistent: false
        //   Watchers do NOT keep the Node.js event loop alive.
        //   This prevents the process from hanging if the
        //   CertificateManager is not properly disposed. The
        //   trade-off is that watchers stop receiving events if
        //   there are no other active handles — acceptable since
        //   CertificateManager always runs alongside a server.
        //
        // awaitWriteFinish: not set
        //   Certificate and CRL files are small (typically < 5 KB)
        //   and written atomically (fs.writeFile). No need to
        //   wait for write stabilization, which would add a 2s+
        //   delay before the in-memory index is updated.
        //
        const usePolling = process.env.OPCUA_PKI_USE_POLLING === "true";
        const envInterval = process.env.OPCUA_PKI_POLLING_INTERVAL
            ? parseInt(process.env.OPCUA_PKI_POLLING_INTERVAL, 10)
            : undefined;
        const pollingInterval = Math.min(10 * 60 * 1000, Math.max(100, envInterval ?? this.folderPollingInterval));
        const chokidarOptions = {
            usePolling,
            ...(usePolling ? { interval: pollingInterval } : {}),
            persistent: false
        };

        // Workaround for two chokidar v4 bugs with persistent:false:
        //
        //   1. Chokidar does not propagate persistent:false to the
        //      underlying fs.watch() handles. Without .unref(), an
        //      undisposed CertificateManager blocks process exit.
        //
        //   2. Chokidar does not register an 'error' handler on
        //      fs.watch when persistent:false (handler.js l.160-168).
        //      On Windows + Node < 22, the native handle fires EPERM
        //      when the watched directory is removed, which becomes
        //      an uncaught exception that crashes the process.
        //
        // We install a single shared fs.watch() interception BEFORE
        // creating all 5 watchers.  Every captured handle gets both
        // an error handler (fix #2) and is later .unref()'d (fix #1).
        //
        // The interception stays active until ALL watchers have
        // emitted "ready" — chokidar creates fs.watch handles
        // asynchronously during directory scanning, so we must keep
        // the interception alive until that completes.
        const allCapturedHandles: fs.FSWatcher[] = [];
        const origWatch = fs.watch;
        let watcherReadyCount = 0;
        const totalWatchers = 5;

        fs.watch = ((...args: Parameters<typeof fs.watch>) => {
            const handle = origWatch.apply(fs, args);
            handle.setMaxListeners(handle.getMaxListeners() + 1);
            handle.on("error", () => {
                /* swallow – watched directory was removed */
            });
            allCapturedHandles.push(handle);
            return handle;
        }) as typeof fs.watch;

        const createUnreffedWatcher = (folder: string) => {
            const startIdx = allCapturedHandles.length;
            const w = chokidar.watch(folder, chokidarOptions);
            const unreffAll = () => {
                // Unref only handles created for THIS watcher
                for (let i = startIdx; i < allCapturedHandles.length; i++) {
                    allCapturedHandles[i].unref();
                }
                // Restore fs.watch once ALL watchers are ready
                watcherReadyCount++;
                if (watcherReadyCount >= totalWatchers) {
                    fs.watch = origWatch;
                }
            };
            return { w, capturedHandles: allCapturedHandles.slice(startIdx), unreffAll };
        };

        // ── Phase 1: Async scan ─────────────────────────────────
        // Populate the in-memory indexes by reading existing
        // files. Uses async readdir/stat to yield the event loop
        // between files. All 5 folders are scanned in parallel.
        await Promise.all([
            this.#scanCertFolder(this.trustedFolder, this.#thumbs.trusted),
            this.#scanCertFolder(this.issuersCertFolder, this.#thumbs.issuers.certs),
            this.#scanCertFolder(this.rejectedFolder, this.#thumbs.rejected),
            this.#scanCrlFolder(this.crlFolder, this.#thumbs.crl),
            this.#scanCrlFolder(this.issuersCrlFolder, this.#thumbs.issuersCrl)
        ]);

        // ── Phase 2: Deferred file watchers ─────────────────────
        // Start chokidar watchers in the background. We do NOT
        // await "ready" so initialize() returns immediately after
        // the sync scan. Chokidar will re-discover existing files
        // (harmless Map overwrites) then watch for live changes.
        this.#startWatcher(this.trustedFolder, this.#thumbs.trusted, createUnreffedWatcher, "trusted");
        this.#startWatcher(this.issuersCertFolder, this.#thumbs.issuers.certs, createUnreffedWatcher, "issuersCerts");
        this.#startWatcher(this.rejectedFolder, this.#thumbs.rejected, createUnreffedWatcher, "rejected");
        this.#startCrlWatcher(this.crlFolder, this.#thumbs.crl, createUnreffedWatcher, "crl");
        this.#startCrlWatcher(this.issuersCrlFolder, this.#thumbs.issuersCrl, createUnreffedWatcher, "issuersCrl");
    }

    /**
     * Scan a certificate folder and populate the in-memory index.
     * Uses async readdir/stat to yield the event loop between
     * file reads, preventing main-loop stalls with large folders.
     */
    async #scanCertFolder(folder: string, index: Map<string, Entry>): Promise<void> {
        if (!fs.existsSync(folder)) return;
        const files = await fs.promises.readdir(folder);
        for (const file of files) {
            const filename = path.join(folder, file);
            try {
                const stat = await fs.promises.stat(filename);
                if (!stat.isFile()) continue;
                const certificate = (await readCertificateChainAsync(filename))[0];
                const info = exploreCertificate(certificate);
                const fingerprint = makeFingerprint(certificate);
                index.set(fingerprint, { certificate, filename, info });
                this.#filenameToHash.set(filename, fingerprint);
            } catch (err) {
                debugLog(`scanCertFolder: skipping ${filename}`, err);
            }
        }
    }

    /**
     * Scan a CRL folder and populate the in-memory CRL index.
     */
    async #scanCrlFolder(folder: string, index: Map<string, CRLData>): Promise<void> {
        if (!fs.existsSync(folder)) return;
        const files = await fs.promises.readdir(folder);
        for (const file of files) {
            const filename = path.join(folder, file);
            try {
                const stat = await fs.promises.stat(filename);
                if (!stat.isFile()) continue;
                this.#onCrlFileAdded(index, filename);
            } catch (err) {
                debugLog(`scanCrlFolder: skipping ${filename}`, err);
            }
        }
        await this.#waitAndCheckCRLProcessingStatus();
    }

    /**
     * Start a chokidar watcher for a CRL folder.
     * Non-blocking — does NOT await "ready".
     */
    #startCrlWatcher(
        folder: string,
        index: Map<string, CRLData>,
        createUnreffedWatcher: (folder: string) => { w: ChokidarFSWatcher; unreffAll: () => void },
        store: CrlStore
    ): void {
        const { w, unreffAll } = createUnreffedWatcher(folder);
        w.on("error", (err: unknown) => {
            debugLog(`chokidar CRL watcher error on ${folder}:`, err);
        });
        let ready = false;

        w.on("unlink", (filename: string) => {
            for (const [key, data] of index.entries()) {
                data.crls = data.crls.filter((c) => c.filename !== filename);
                if (data.crls.length === 0) {
                    index.delete(key);
                }
            }
            if (ready) {
                this.emit("crlRemoved", { store, filename });
            }
        });
        w.on("add", (filename: string) => {
            if (ready) {
                this.#onCrlFileAdded(index, filename);
                this.emit("crlAdded", { store, filename });
            }
        });
        w.on("change", (changedPath: string) => {
            debugLog("change in folder ", folder, changedPath);
        });
        this.#watchers.push(w as unknown as fs.FSWatcher);
        this.#pendingUnrefs.add(unreffAll);
        w.on("ready", () => {
            ready = true;
            this.#pendingUnrefs.delete(unreffAll);
            unreffAll();
        });
    }

    /**
     * Start a chokidar watcher for a certificate folder.
     * Non-blocking — does NOT await "ready".
     */
    #startWatcher(
        folder: string,
        index: Map<string, Entry>,
        createUnreffedWatcher: (folder: string) => { w: ChokidarFSWatcher; unreffAll: () => void },
        store: CertificateStore
    ): void {
        const { w, unreffAll } = createUnreffedWatcher(folder);
        w.on("error", (err: unknown) => {
            debugLog(`chokidar cert watcher error on ${folder}:`, err);
        });
        let ready = false;
        w.on("unlink", (filename: string) => {
            debugLog(chalk.cyan(`unlink in folder ${folder}`), filename);
            const h = this.#filenameToHash.get(filename);
            if (h && index.has(h)) {
                index.delete(h);
                this.emit("certificateRemoved", { store, fingerprint: h, filename });
            }
        });
        w.on("add", (filename: string) => {
            debugLog(chalk.cyan(`add in folder ${folder}`), filename);
            try {
                const certificate = readCertificateChain(filename)[0];
                const info = exploreCertificate(certificate);
                const fingerprint = makeFingerprint(certificate);

                const isNew = !index.has(fingerprint);
                index.set(fingerprint, { certificate, filename, info });
                this.#filenameToHash.set(filename, fingerprint);

                debugLog(
                    chalk.magenta("CERT"),
                    info.tbsCertificate.subjectFingerPrint,
                    info.tbsCertificate.serialNumber,
                    info.tbsCertificate.extensions?.authorityKeyIdentifier?.authorityCertIssuerFingerPrint
                );
                if (ready || isNew) {
                    this.emit("certificateAdded", { store, certificate, fingerprint, filename });
                }
            } catch (err) {
                debugLog(`Walk files in folder ${folder} with file ${filename}`);
                debugLog(err);
            }
        });
        w.on("change", (changedPath: string) => {
            debugLog(chalk.cyan(`change in folder ${folder}`), changedPath);
            try {
                const certificate = readCertificateChain(changedPath)[0];
                const newFingerprint = makeFingerprint(certificate);
                const oldHash = this.#filenameToHash.get(changedPath);
                if (oldHash && oldHash !== newFingerprint) {
                    index.delete(oldHash);
                }
                index.set(newFingerprint, { certificate, filename: changedPath, info: exploreCertificate(certificate) });
                this.#filenameToHash.set(changedPath, newFingerprint);
                this.emit("certificateChange", { store, certificate, fingerprint: newFingerprint, filename: changedPath });
            } catch (err) {
                debugLog(`change event: failed to re-read ${changedPath}`, err);
            }
        });
        this.#watchers.push(w as unknown as fs.FSWatcher);
        this.#pendingUnrefs.add(unreffAll);
        w.on("ready", () => {
            ready = true;
            this.#pendingUnrefs.delete(unreffAll);
            unreffAll();
            debugLog("ready");
            debugLog([...index.keys()].map((k) => k.substring(0, 10)));
        });
    }

    // make sure that all crls have been processed.
    async #waitAndCheckCRLProcessingStatus(): Promise<void> {
        return new Promise((resolve, _reject) => {
            if (this.#pendingCrlToProcess === 0) {
                setImmediate(resolve);
                return;
            }
            this.#onCrlProcessWaiters.push(resolve);
        });
    }
}

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
import { withLock } from "@ster5/global-mutex";
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
    readCertificate,
    readCertificateAsync,
    readCertificateRevocationList,
    split_der,
    toPem,
    verifyCertificateChain,
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
        entry.info = exploreCertificateCached(entry.certificate);
    }
    return entry.info;
}

/**
 * Module-level LRU cache for `exploreCertificate()` results.
 *
 * During a single `verifyCertificate()` flow the same certificate
 * buffer can be parsed 4-6 times across different helper functions.
 * This cache deduplicates the ASN.1 DER parsing by keying on the
 * SHA-1 thumbprint of the certificate buffer.
 *
 * The cache is deliberately small (8 entries) so it covers the
 * "same-cert-in-one-verification-flow" case without unbounded
 * memory growth.
 */
const EXPLORE_CACHE_MAX = 8;
const _exploreCache = new Map<string, CertificateInternals>();

function exploreCertificateCached(certificate: Certificate): CertificateInternals {
    const key = makeSHA1Thumbprint(certificate).toString("hex");
    const cached = _exploreCache.get(key);
    if (cached) {
        // Move to end (most-recently-used)
        _exploreCache.delete(key);
        _exploreCache.set(key, cached);
        return cached;
    }
    const info = exploreCertificate(certificate);
    _exploreCache.set(key, info);
    if (_exploreCache.size > EXPLORE_CACHE_MAX) {
        // Evict oldest (first key in insertion order)
        const oldest = _exploreCache.keys().next().value;
        if (oldest) _exploreCache.delete(oldest);
    }
    return info;
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

function makeFingerprint(certificate: Certificate | CertificateRevocationList): string {
    // When the buffer contains a certificate chain (multiple
    // concatenated DER structures), the thumbprint must be
    // computed on the leaf certificate only (first element).
    const chain = split_der(certificate);
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
        const commonName = exploreCertificateCached(certificate).tbsCertificate.subject.commonName || "";
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
    const info = exploreCertificateCached(certificate);
    return isSelfSigned2(info);
}

/**
 * Find the issuer certificate for a given certificate within
 * a provided certificate chain.
 *
 * @param certificate - the DER-encoded certificate whose issuer to find
 * @param chain - candidate issuer certificates to search
 * @returns the matching issuer certificate, or `null` if not found
 */
export function findIssuerCertificateInChain(certificate: Certificate, chain: Certificate[]): Certificate | null {
    if (!certificate) {
        return null;
    }
    const certInfo = exploreCertificateCached(certificate);

    // istanbul ignore next
    if (isSelfSigned2(certInfo)) {
        // the certificate is self signed so is it's own issuer.
        return certificate;
    }
    const wantedIssuerKey = certInfo.tbsCertificate.extensions?.authorityKeyIdentifier?.keyIdentifier;

    // istanbul ignore next
    if (!wantedIssuerKey) {
        // Certificate has no extension 3 ! the certificate might have been generated by an old system
        debugLog("Certificate has no extension 3");
        return null;
    }
    const potentialIssuers = chain.filter((c) => {
        const info = exploreCertificateCached(c);
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
    public async isCertificateTrusted(certificate: Certificate): Promise<string> {
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
        certificate: Certificate,
        _isIssuer: boolean,
        level: number,
        options: VerifyCertificateOptions
    ): Promise<VerificationStatus> {
        if (level >= 5) {
            // maximum level of certificate in chain reached !
            return VerificationStatus.BadSecurityChecksFailed;
        }
        const chain = split_der(certificate);
        debugLog("NB CERTIFICATE IN CHAIN = ", chain.length);
        const info = exploreCertificateCached(chain[0]);

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
                    if (!options || !options.acceptOutDatedIssuerCertificate) {
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
                const isCertificateSignatureOK = verifyCertificateSignature(certificate, issuerCertificate);
                if (!isCertificateSignatureOK) {
                    debugLog(" the certificate was not signed by the issuer as it claim to be ! Danger");
                    return VerificationStatus.BadSecurityChecksFailed;
                }
                hasValidIssuer = true;

                // let detected if our certificate is in the revocation list
                let revokedStatus = await this.isCertificateRevoked(certificate);
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
                const isCertificateSignatureOK = verifyCertificateSignature(certificate, certificate);
                if (!isCertificateSignatureOK) {
                    debugLog("Self-signed Certificate signature is not valid");
                    return VerificationStatus.BadSecurityChecksFailed;
                }
                const revokedStatus = await this.isCertificateRevoked(certificate);
                debugLog("revokedStatus of self signed certificate:", revokedStatus);
            }
        }

        const status = await this.#checkRejectedOrTrusted(certificate);
        if (status === "rejected") {
            if (!(options.acceptCertificateWithValidIssuerChain && hasValidIssuer && hasTrustedIssuer)) {
                return VerificationStatus.BadCertificateUntrusted;
            }
        }
        const _c2 = chain[1] ? exploreCertificateInfo(chain[1]) : "non";
        debugLog("chain[1] info=", _c2);

        // Has SoftwareCertificate passed its issue date and has it not expired ?
        // check dates
        const certificateInfo = exploreCertificateInfo(certificate);
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
        certificate: Certificate,
        options: VerifyCertificateOptions
    ): Promise<VerificationStatus> {
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
    public async verifyCertificate(certificate: Certificate, options?: VerifyCertificateOptions): Promise<VerificationStatus> {
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
                const filename = path.join(folder, `crl_${buildIdealCertificateName(crl)}.pem`);
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
        const issuerInfo = exploreCertificateCached(issuerCertificate);
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
     * The certificate buffer may contain a single certificate or a
     * full chain (leaf + issuer certificates concatenated in DER).
     * Only the leaf certificate is added to the trusted store.
     *
     * When the chain contains issuer certificates, this method
     * verifies that each issuer is already registered via
     * {@link addIssuer} before trusting the leaf.
     *
     * If one of the certificates in the chain is not registered in the issuers store,
     * the leaf certificate will be rejected.
     *
     * @param certificateChain - DER-encoded certificate or chain
     * @returns `VerificationStatus.Good` on success, or an error
     *  status indicating why the certificate was rejected.
     */
    public async addTrustedCertificateFromChain(certificateChain: Certificate): Promise<VerificationStatus> {
        const certificates = split_der(certificateChain);
        const leafCertificate = certificates[0];

        // Structural validation — can we parse it?
        try {
            exploreCertificateCached(leafCertificate);
        } catch (_err) {
            return VerificationStatus.BadCertificateInvalid;
        }

        // Lightweight chain validation — verify the certificate
        // structure and signature without trust-store side-effects
        const result = await verifyCertificateChain([leafCertificate]);
        if (result.status !== "Good") {
            return VerificationStatus.BadCertificateInvalid;
        }

        // If a chain was provided, verify that every issuer in the
        // chain is already registered in the issuers store.
        // if one of the certificates in the chain is not registered in the issuers store,
        // the certificate will be rejected.
        if (certificates.length > 1) {
            // Re-scan the issuers folder to pick up certificates
            // added directly to disk (e.g. by GDS push or external
            // tooling) that the file-system watcher may not have
            // delivered yet.
            await this.#scanCertFolder(this.issuersCertFolder, this.#thumbs.issuers.certs);
            for (const issuerCert of certificates.slice(1)) {
                const thumbprint = makeFingerprint(issuerCert);
                if (!(await this.hasIssuer(thumbprint))) {
                    // this issuer certificate is not registered in the issuers store
                    // reject the leaf certificate
                    return VerificationStatus.BadCertificateChainIncomplete;
                }
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
    public async findIssuerCertificate(certificate: Certificate): Promise<Certificate | null> {
        const certInfo = exploreCertificateCached(certificate);

        if (isSelfSigned2(certInfo)) {
            // the certificate is self signed so is it's own issuer.
            return certificate;
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
    async #checkRejectedOrTrusted(certificate: Buffer): Promise<CertificateStatus> {
        const fingerprint = makeFingerprint(certificate);

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
        const issuerCertificateInfo = exploreCertificateCached(issuerCertificate);
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
        certificate: Certificate,
        issuerCertificate?: Certificate | null
    ): Promise<VerificationStatus> {
        if (isSelfSigned3(certificate)) {
            return VerificationStatus.Good;
        }

        if (!issuerCertificate) {
            issuerCertificate = await this.findIssuerCertificate(certificate);
        }
        if (!issuerCertificate) {
            return VerificationStatus.BadCertificateChainIncomplete;
        }
        const crls = this.#findAssociatedCRLs(issuerCertificate);

        if (!crls) {
            return VerificationStatus.BadCertificateRevocationUnknown;
        }
        const certInfo = exploreCertificateCached(certificate);
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
                const certificate = await readCertificateAsync(filename);
                const info = exploreCertificateCached(certificate);
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
                const certificate = readCertificate(filename);
                const info = exploreCertificateCached(certificate);
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
                const certificate = readCertificate(changedPath);
                const newFingerprint = makeFingerprint(certificate);
                const oldHash = this.#filenameToHash.get(changedPath);
                if (oldHash && oldHash !== newFingerprint) {
                    index.delete(oldHash);
                }
                index.set(newFingerprint, { certificate, filename: changedPath, info: exploreCertificateCached(certificate) });
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

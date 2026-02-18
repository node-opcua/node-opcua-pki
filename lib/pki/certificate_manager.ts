/* eslint-disable @typescript-eslint/no-explicit-any */
// ---------------------------------------------------------------------------------------------------------------------
// node-opcua
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2025 - Sterfive.com
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
// tslint:disable:no-shadowed-variable
// tslint:disable:member-ordering

import assert from "assert";
import chalk from "chalk";
import chokidar from "chokidar";
import fs from "fs";
import path from "path";

import { withLock } from "@ster5/global-mutex";
import {
    Certificate,
    CertificateInternals,
    CertificateRevocationList,
    CertificateRevocationListInfo,
    DER,
    exploreCertificate,
    exploreCertificateInfo,
    exploreCertificateRevocationList,
    generatePrivateKeyFile,
    makeSHA1Thumbprint,
    readCertificate,
    readCertificateRevocationList,
    split_der,
    toPem,
    verifyCertificateSignature,
} from "node-opcua-crypto";

import { SubjectOptions } from "../misc/subject";
import { CertificateStatus, Filename, KeySize, Thumbprint } from "../toolbox/common";

import { debugLog, warningLog } from "../toolbox/debug";
import { makePath, mkdirRecursiveSync } from "../toolbox/common2";

import { CreateSelfSignCertificateParam, CreateSelfSignCertificateWithConfigParam } from "../toolbox/common";
import { createCertificateSigningRequestAsync, createSelfSignedCertificate } from "../toolbox/without_openssl";

import _simple_config_template from "./templates/simple_config_template.cnf";
/**
 *
 * a minimalist config file for openssl that allows
 * self-signed certificate to be generated.
 *
 */
// tslint:disable-next-line:variable-name
const configurationFileSimpleTemplate: string = _simple_config_template;
const fsWriteFile = fs.promises.writeFile;

interface Entry {
    certificate: Certificate;
    filename: string;
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
    trusted: { [key: string]: Entry };
    rejected: { [key: string]: Entry };
    issuers: {
        certs: { [key: string]: Entry };
    };
    crl: {
        [key: string]: CRLData; // key is subjectFingerPrint of issuer Certificate
    };
    issuersCrl: {
        [key: string]: CRLData; // key is subjectFingerPrint of issuer Certificate
    };
}

export interface CertificateManagerOptions {
    keySize?: KeySize;
    location: string;
}

export interface CreateSelfSignCertificateParam1 extends CreateSelfSignCertificateParam {
    outputFile?: Filename; // default : own/cert/self_signed_certificate.pem
    subject: SubjectOptions | string;
    applicationUri: string;
    dns: string[];
    startDate: Date;
    validity: number;
}

export interface VerifyCertificateOptions {
    acceptOutdatedCertificate?: boolean;
    acceptOutDatedIssuerCertificate?: boolean;
    ignoreMissingRevocationList?: boolean;
    acceptPendingCertificate?: boolean;
    // rejectSelfSignedCertificate: boolean;
}

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
    Good = "Good",
}

function makeFingerprint(certificate: Certificate | CertificateRevocationList): string {
    return makeSHA1Thumbprint(certificate).toString("hex");
}
function short(stringToShorten: string) {
    return stringToShorten.substring(0, 10);
}
const forbiddenChars = /[\x00-\x1F<>:"\/\\|?*]/g;
function buildIdealCertificateName(certificate: Certificate): string {
    const fingerprint = makeFingerprint(certificate);
    try {
        const commonName = exploreCertificate(certificate).tbsCertificate.subject.commonName || "";
        // commonName may contain invalid characters for a filename such as / or \ or :
        // that we need to replace with a valid character.
        // replace / or \ or : with _
        const sanitizedCommonName = commonName.replace(forbiddenChars, "_");
        return sanitizedCommonName + "[" + fingerprint + "]";
    } catch (err) {
        // make be certificate is incorrect !
        return "invalid_certificate_[" + fingerprint + "]";
    }
}
function findMatchingIssuerKey(entries: Entry[], wantedIssuerKey: string): Entry[] {
    const selected = entries.filter(({ certificate }) => {
        const info = exploreCertificate(certificate);
        return info.tbsCertificate.extensions && info.tbsCertificate.extensions.subjectKeyIdentifier === wantedIssuerKey;
    });
    return selected;
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

export function findIssuerCertificateInChain(certificate: Certificate, chain: Certificate[]): Certificate | null {
    if (!certificate) {
        return null;
    }
    const certInfo = exploreCertificate(certificate);

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
        const info = exploreCertificate(c);
        return info.tbsCertificate.extensions && info.tbsCertificate.extensions.subjectKeyIdentifier === wantedIssuerKey;
        return true;
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

export enum CertificateManagerState {
    Uninitialized = 0,
    Initializing = 1,
    Initialized = 2,
    Disposing = 3,
    Disposed = 4,
}
export class CertificateManager {
    public untrustUnknownCertificate = true;
    public state: CertificateManagerState = CertificateManagerState.Uninitialized;
    public folderPoolingInterval = 5000;

    private readonly keySize: KeySize;
    private readonly location: string;
    private readonly _watchers: fs.FSWatcher[] = [];
    private _readCertificatesCalled = false;
    private readonly _filenameToHash: { [key: string]: string } = {};

    private readonly _thumbs: Thumbs = {
        rejected: {},
        trusted: {},
        issuers: {
            certs: {},
        },
        crl: {},
        issuersCrl: {},
    };

    constructor(options: CertificateManagerOptions) {
        options.keySize = options.keySize || 2048;
        assert(Object.prototype.hasOwnProperty.call(options, "location"));
        assert(Object.prototype.hasOwnProperty.call(options, "keySize"));
        assert(this.state === CertificateManagerState.Uninitialized);

        this.location = makePath(options.location, "");
        this.keySize = options.keySize;

        mkdirRecursiveSync(options.location);

        // istanbul ignore next
        if (!fs.existsSync(this.location)) {
            throw new Error("CertificateManager cannot access location " + this.location);
        }
    }

    get configFile() {
        return path.join(this.rootDir, "own/openssl.cnf");
    }

    get rootDir() {
        return this.location;
    }

    get privateKey() {
        return path.join(this.rootDir, "own/private/private_key.pem");
    }

    get randomFile() {
        return path.join(this.rootDir, "./random.rnd");
    }

    /**
     * returns the certificate status trusted/rejected
     * @param certificate
     */
    public async getCertificateStatus(certificate: Buffer): Promise<CertificateStatus> {
        await this.initialize();
        let status = await this._checkRejectedOrTrusted(certificate);
        if (status === "unknown") {
            assert(certificate instanceof Buffer);

            const pem = toPem(certificate, "CERTIFICATE");
            const fingerprint = makeFingerprint(certificate);
            const filename = path.join(this.rejectedFolder, buildIdealCertificateName(certificate) + ".pem");
            await fs.promises.writeFile(filename, pem);
            this._thumbs.rejected[fingerprint] = {
                certificate,
                filename,
            };
            status = "rejected";
        }
        return status;
    }

    public async rejectCertificate(certificate: Certificate): Promise<void> {
        await this._moveCertificate(certificate, "rejected");
    }

    public async trustCertificate(certificate: Certificate): Promise<void> {
        await this._moveCertificate(certificate, "trusted");
    }

    public get rejectedFolder(): string {
        return path.join(this.rootDir, "rejected");
    }
    public get trustedFolder(): string {
        return path.join(this.rootDir, "trusted/certs");
    }
    public get crlFolder(): string {
        return path.join(this.rootDir, "trusted/crl");
    }
    public get issuersCertFolder(): string {
        return path.join(this.rootDir, "issuers/certs");
    }
    public get issuersCrlFolder(): string {
        return path.join(this.rootDir, "issuers/crl");
    }

    public async isCertificateTrusted(certificate: Certificate): Promise<string> {
        const fingerprint = makeFingerprint(certificate) as Thumbprint;
        const certificateInTrust = this._thumbs.trusted[fingerprint]?.certificate;

        if (certificateInTrust) {
            return "Good";
        } else {
            const certificateInRejected = this._thumbs.rejected[fingerprint];
            if (!certificateInRejected) {
                const certificateFilenameInRejected = path.join(
                    this.rejectedFolder,
                    buildIdealCertificateName(certificate) + ".pem",
                );
                if (!this.untrustUnknownCertificate) {
                    return "Good";
                }
                // Certificate should be mark as untrusted
                // let's first verify that certificate is valid ,as we don't want to write invalid data
                try {
                    const certificateInfo = exploreCertificateInfo(certificate);
                    certificateInfo;
                } catch (err) {
                    return "BadCertificateInvalid";
                }
                debugLog("certificate has never been seen before and is now rejected (untrusted) ", certificateFilenameInRejected);
                await fsWriteFile(certificateFilenameInRejected, toPem(certificate, "CERTIFICATE"));
            }
            return "BadCertificateUntrusted";
        }
    }
    public async _innerVerifyCertificateAsync(
        certificate: Certificate,
        isIssuer: boolean,
        level: number,
        options: VerifyCertificateOptions,
    ): Promise<VerificationStatus> {
        if (level >= 5) {
            // maximum level of certificate in chain reached !
            return VerificationStatus.BadSecurityChecksFailed;
        }
        const chain = split_der(certificate);
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
                    info.tbsCertificate.extensions?.authorityKeyIdentifier?.keyIdentifier,
                );
                let issuerCertificate = await this.findIssuerCertificate(chain[0]);
                if (!issuerCertificate) {
                    // the issuer has not been found in the list of trusted certificate
                    // may be the issuer certificate is in the chain itself ?
                    issuerCertificate = findIssuerCertificateInChain(chain[0], chain);
                    if (!issuerCertificate) {
                        debugLog(
                            " the issuer has not been found in the chain itself nor in the issuer.cert list => the chain is incomplete!",
                        );
                        return VerificationStatus.BadCertificateChainIncomplete;
                    }
                    debugLog(" the issuer certificate has been found in the chain itself ! the chain is complete !");
                } else {
                    debugLog(" the issuer certificate has been found in the issuer.cert folder !");
                }
                const issuerStatus = await this._innerVerifyCertificateAsync(issuerCertificate, true, level + 1, options);
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
                if (issuerStatus == VerificationStatus.BadCertificateUntrusted) {
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
                    if (options && options.ignoreMissingRevocationList) {
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
                const issuerTrustedStatus = await this._checkRejectedOrTrusted(issuerCertificate);
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

        const status = await this._checkRejectedOrTrusted(certificate);
        if (status === "rejected") {
            return VerificationStatus.BadCertificateUntrusted;
        }

        const c2 = chain[1] ? exploreCertificateInfo(chain[1]) : "non";
        c2;

        // Has SoftwareCertificate passed its issue date and has it not expired ?
        // check dates
        const certificateInfo = exploreCertificateInfo(certificate);
        const now = new Date();

        let isTimeInvalid = false;
        // check that certificate is active
        if (certificateInfo.notBefore.getTime() > now.getTime()) {
            // certificate is not active yet
            debugLog(
                chalk.red("certificate is invalid : certificate is not active yet !") +
                "  not before date =" +
                certificateInfo.notBefore,
            );
            if (!options.acceptPendingCertificate) {
                isTimeInvalid = true;
            }
        }

        //  check that certificate has not expired
        if (certificateInfo.notAfter.getTime() <= now.getTime()) {
            // certificate is obsolete
            debugLog(
                chalk.red("certificate is invalid : certificate has expired !") + " not after date =" + certificateInfo.notAfter,
            );
            if (!options.acceptOutdatedCertificate) {
                isTimeInvalid = true;
            }
        }
        if (status === "trusted") {
            return isTimeInvalid ? VerificationStatus.BadCertificateTimeInvalid : VerificationStatus.Good;
        }
        assert(status === "unknown");
        if (hasIssuerKey) {
            if (!hasTrustedIssuer) {
                return VerificationStatus.BadCertificateUntrusted;
            }
            if (!hasValidIssuer) {
                return VerificationStatus.BadCertificateUntrusted;
            }
            return isTimeInvalid ? VerificationStatus.BadCertificateTimeInvalid : VerificationStatus.Good;
        } else {
            return VerificationStatus.BadCertificateUntrusted;
        }
    }

    protected async verifyCertificateAsync(
        certificate: Certificate,
        options: VerifyCertificateOptions,
    ): Promise<VerificationStatus> {
        const status1 = await this._innerVerifyCertificateAsync(certificate, false, 0, options);
        return status1;
    }

    /**
     * Verify certificate validity
     * @method verifyCertificate
     * @param certificate
     */
    public async verifyCertificate(certificate: Certificate, options?: VerifyCertificateOptions): Promise<VerificationStatus> {
        type F = (err: Error | null, status?: VerificationStatus) => void;

        // Is the  signature on the SoftwareCertificate valid .?
        if (!certificate) {
            // missing certificate
            return VerificationStatus.BadSecurityChecksFailed;
        }
        return await this.verifyCertificateAsync(certificate, options || {});
    }

    /*
     *
     *  PKI
     *    +---> trusted
     *    +---> rejected
     *    +---> own
     *           +---> cert
     *           +---> own
     *
     */
    public async initialize(): Promise<void> {
        if (this.state !== CertificateManagerState.Uninitialized) {
            return;
        }
        this.state = CertificateManagerState.Initializing;
        await this._initialize();
        this.state = CertificateManagerState.Initialized;
    }
    private async _initialize(): Promise<void> {
        assert((this.state = CertificateManagerState.Initializing));
        const pkiDir = this.location;
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
                assert(this.state !== CertificateManagerState.Disposing);
                if (this.state === CertificateManagerState.Disposed) {
                    return;
                }
                assert(this.state === CertificateManagerState.Initializing);

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
                    await this._readCertificates();
                } else {
                    // debugLog("   initialize :  private key already exists ... skipping");
                    await this._readCertificates();
                }
            });
        } else {
            await this._readCertificates();
        }
    }

    public async dispose(): Promise<void> {
        if (this.state === CertificateManagerState.Disposing) {
            throw new Error("Already disposing");
        }

        if (this.state === CertificateManagerState.Uninitialized) {
            this.state = CertificateManagerState.Disposed;
            return;
        }

        // wait for initialization to be completed
        if (this.state === CertificateManagerState.Initializing) {
            await new Promise((resolve) => setTimeout(resolve, 100));
            return await this.dispose();
        }

        try {
            this.state = CertificateManagerState.Disposing;
            await Promise.all(this._watchers.map((w) => w.close()));
            this._watchers.forEach((w) => w.removeAllListeners());
            this._watchers.splice(0);
        } finally {
            this.state = CertificateManagerState.Disposed;
        }
    }

    protected async withLock2<T>(action: () => Promise<T>): Promise<T> {
        const lockFileName = path.join(this.rootDir, "mutex.lock");
        return withLock<T>({ fileToLock: lockFileName }, async () => {
            return await action();
        });
    }
    /**
     *
     * create a self-signed certificate for the CertificateManager private key
     *
     */
    public async createSelfSignedCertificate(params: CreateSelfSignCertificateParam1): Promise<void> {
        assert(typeof params.applicationUri === "string", "expecting applicationUri");
        if (!fs.existsSync(this.privateKey)) {
            throw new Error("Cannot find private key " + this.privateKey);
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

    public async createCertificateRequest(params: CreateSelfSignCertificateParam): Promise<Filename> {
        assert(params);
        const _params = params as CreateSelfSignCertificateWithConfigParam;
        if (Object.prototype.hasOwnProperty.call(_params, "rootDir")) {
            throw new Error("rootDir should not be specified ");
        }
        assert(!_params.rootDir);
        assert(!_params.configFile);
        assert(!_params.privateKey);
        _params.rootDir = path.resolve(this.rootDir);
        _params.configFile = path.resolve(this.configFile);
        _params.privateKey = path.resolve(this.privateKey);

        return await this.withLock2<string>(async () => {
            // compose a file name for the request
            const now = new Date();
            const today = now.toISOString().slice(0, 10) + "_" + now.getTime();
            const certificateSigningRequestFilename = path.join(this.rootDir, "own/certs", "certificate_" + today + ".csr");
            await createCertificateSigningRequestAsync(certificateSigningRequestFilename, _params);
            return certificateSigningRequestFilename;
        });
    }

    public async addIssuer(certificate: DER, validate = false, addInTrustList = false): Promise<VerificationStatus> {
        if (validate) {
            const status = await this.verifyCertificate(certificate);
            if (status !== VerificationStatus.Good && status !== VerificationStatus.BadCertificateUntrusted) {
                return status;
            }
        }
        const pemCertificate = toPem(certificate, "CERTIFICATE");
        const fingerprint = makeFingerprint(certificate);
        if (this._thumbs.issuers.certs[fingerprint]) {
            // already in .. simply ignore
            return VerificationStatus.Good;
        }
        // write certificate
        const filename = path.join(this.issuersCertFolder, "issuer_" + buildIdealCertificateName(certificate) + ".pem");
        await fs.promises.writeFile(filename, pemCertificate, "ascii");

        // first time seen, let's save it.
        this._thumbs.issuers.certs[fingerprint] = { certificate, filename };

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
                const index = target === "trusted" ? this._thumbs.crl : this._thumbs.issuersCrl;
                const folder = target === "trusted" ? this.crlFolder : this.issuersCrlFolder;

                const crlInfo = exploreCertificateRevocationList(crl);
                const key = crlInfo.tbsCertList.issuerFingerprint;
                if (!index[key]) {
                    index[key] = { crls: [], serialNumbers: {} };
                }
                const pemCertificate = toPem(crl, "X509 CRL");
                const filename = path.join(folder, "crl_" + buildIdealCertificateName(crl) + ".pem");
                await fs.promises.writeFile(filename, pemCertificate, "ascii");

                await this._on_crl_file_added(index, filename);

                await this.waitAndCheckCRLProcessingStatus();

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
    public async clearRevocationLists(
        target: "issuers" | "trusted" | "all"
    ): Promise<void> {
        const clearFolder = async (
            folder: string,
            index: { [key: string]: CRLData }
        ) => {
            try {
                const files = await fs.promises.readdir(folder);
                for (const file of files) {
                    const ext = path.extname(file).toLowerCase();
                    if (ext === ".crl" || ext === ".pem" || ext === ".der") {
                        await fs.promises.unlink(path.join(folder, file));
                    }
                }
            } catch (err: any) {
                if (err.code !== "ENOENT") {
                    throw err;
                }
            }
            // Clear the in-memory index
            for (const key of Object.keys(index)) {
                delete index[key];
            }
        };

        if (target === "issuers" || target === "all") {
            await clearFolder(this.issuersCrlFolder, this._thumbs.issuersCrl);
        }
        if (target === "trusted" || target === "all") {
            await clearFolder(this.crlFolder, this._thumbs.crl);
        }
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
        const certInfo = exploreCertificate(certificate);

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

        const issuerCertificates = Object.values(this._thumbs.issuers.certs);

        const selectedIssuerCertificates = findMatchingIssuerKey(issuerCertificates, wantedIssuerKey);

        if (selectedIssuerCertificates.length > 0) {
            if (selectedIssuerCertificates.length > 1) {
                // tslint:disable-next-line: no-console
                warningLog("Warning more than one issuer certificate exists with subjectKeyIdentifier ", wantedIssuerKey);
            }
            return selectedIssuerCertificates[0].certificate || null;
        }
        // check also in trusted  list
        const trustedCertificates = Object.values(this._thumbs.trusted);
        const selectedTrustedCertificates = findMatchingIssuerKey(trustedCertificates, wantedIssuerKey);

        // istanbul ignore next
        if (selectedTrustedCertificates.length > 1) {
            // tslint:disable-next-line: no-console
            warningLog(
                "Warning more than one certificate exists with subjectKeyIdentifier in trusted certificate list ",
                wantedIssuerKey,
                selectedTrustedCertificates.length,
            );

        }
        return selectedTrustedCertificates.length > 0 ? selectedTrustedCertificates[0].certificate : null;
    }

    /**
     * @internal
     * @private
     */
    public async _checkRejectedOrTrusted(certificate: Buffer): Promise<CertificateStatus> {
        assert(certificate instanceof Buffer);
        const fingerprint = makeFingerprint(certificate);

        debugLog("_checkRejectedOrTrusted fingerprint ", short(fingerprint));

        await this._readCertificates();

        if (Object.prototype.hasOwnProperty.call(this._thumbs.rejected, fingerprint)) {
            return "rejected";
        }
        if (Object.prototype.hasOwnProperty.call(this._thumbs.trusted, fingerprint)) {
            return "trusted";
        }
        return "unknown";
    }

    private async _moveCertificate(certificate: Certificate, newStatus: CertificateStatus) {
        // a mutex is requested here

        assert(certificate instanceof Buffer);
        const fingerprint = makeFingerprint(certificate);

        const status = await this.getCertificateStatus(certificate);
        debugLog("_moveCertificate", fingerprint.substring(0, 10), "from", status, "to", newStatus);
        assert(status === "rejected" || status === "trusted");

        if (status !== newStatus) {
            const certificateSrc = (this._thumbs as any)[status!][fingerprint]?.filename;

            // istanbul ignore next
            if (!certificateSrc) {
                debugLog(" cannot find certificate ", fingerprint.substring(0, 10), " in", this._thumbs, [status!]);
                throw new Error("internal");
            }
            const destFolder =
                newStatus === "rejected" ? this.rejectedFolder : newStatus === "trusted" ? this.trustedFolder : this.rejectedFolder;
            const certificateDest = path.join(destFolder, path.basename(certificateSrc));

            debugLog("_moveCertificate1", fingerprint.substring(0, 10), "old name", certificateSrc);
            debugLog("_moveCertificate1", fingerprint.substring(0, 10), "new name", certificateDest);
            await fs.promises.rename(certificateSrc, certificateDest);
            delete (this._thumbs as any)[status!][fingerprint];
            (this._thumbs as any)[newStatus][fingerprint] = {
                certificate,
                filename: certificateDest,
            };
        }
    }
    private _findAssociatedCRLs(issuerCertificate: Certificate): CRLData | null {
        const issuerCertificateInfo = exploreCertificate(issuerCertificate);
        const key = issuerCertificateInfo.tbsCertificate.subjectFingerPrint;
        return this._thumbs.issuersCrl[key] ? this._thumbs.issuersCrl[key] : this._thumbs.crl[key] ? this._thumbs.crl[key] : null;
    }

    public async isCertificateRevoked(
        certificate: Certificate,
        issuerCertificate?: Certificate | null,
    ): Promise<VerificationStatus> {
        // istanbul ignore next
        if (isSelfSigned3(certificate)) {
            return VerificationStatus.Good;
        }

        if (!issuerCertificate) {
            issuerCertificate = await this.findIssuerCertificate(certificate);
        }
        if (!issuerCertificate) {
            return VerificationStatus.BadCertificateChainIncomplete;
        }
        const crls = this._findAssociatedCRLs(issuerCertificate);

        if (!crls) {
            return VerificationStatus.BadCertificateRevocationUnknown;
        }
        const certInfo = exploreCertificate(certificate);
        const serialNumber =
            certInfo.tbsCertificate.serialNumber || certInfo.tbsCertificate.extensions?.authorityKeyIdentifier?.serial || "";

        const key = certInfo.tbsCertificate.extensions?.authorityKeyIdentifier?.authorityCertIssuerFingerPrint || "<unknown>";
        const crl2 = this._thumbs.crl[key] || null;

        if (crls.serialNumbers[serialNumber] || (crl2 && crl2.serialNumbers[serialNumber])) {
            return VerificationStatus.BadCertificateRevoked;
        }
        return VerificationStatus.Good;
    }

    private _pending_crl_to_process = 0;
    private _on_crl_process?: () => void;
    private queue: any[] = [];
    private _on_crl_file_added(index: { [key: string]: CRLData }, filename: string) {
        this.queue.push({ index, filename });
        this._pending_crl_to_process += 1;
        if (this._pending_crl_to_process === 1) {
            this._process_next_crl();
        }
    }
    private async _process_next_crl() {
        try {
            const { index, filename } = this.queue.shift();
            const crl = await readCertificateRevocationList(filename);
            const crlInfo = exploreCertificateRevocationList(crl);
            debugLog(chalk.cyan("add CRL in folder "), filename); // stat);
            const fingerprint = crlInfo.tbsCertList.issuerFingerprint;
            index[fingerprint] = index[fingerprint] || {
                crls: [],
                serialNumbers: {},
            };
            index[fingerprint].crls.push({ crlInfo, filename });

            const serialNumbers = index[fingerprint].serialNumbers;
            // now inject serial numbers
            for (const revokedCertificate of crlInfo.tbsCertList.revokedCertificates) {
                const serialNumber = revokedCertificate.userCertificate;
                if (!serialNumbers[serialNumber]) {
                    serialNumbers[serialNumber] = revokedCertificate.revocationDate;
                }
            }
            debugLog(chalk.cyan("CRL"), fingerprint, "serial numbers = ", Object.keys(serialNumbers)); // stat);
        } catch (err) {
            debugLog("CRL filename error =");
            debugLog(err);
        }
        this._pending_crl_to_process -= 1;
        if (this._pending_crl_to_process === 0) {
            if (this._on_crl_process) {
                this._on_crl_process();
                this._on_crl_process = undefined;
            }
        } else {
            this._process_next_crl();
        }
    }
    private async _readCertificates(): Promise<void> {
        if (this._readCertificatesCalled) {
            return;
        }
        this._readCertificatesCalled = true;

        const options = {
            usePolling: true,
            interval: Math.min(10 * 60 * 1000, Math.max(100, this.folderPoolingInterval)),
            persistent: false,
            awaitWriteFinish: {
                stabilityThreshold: 2000,
                pollInterval: 600,
            },
        };
        async function _walkCRLFiles(this: CertificateManager, folder: string, index: { [key: string]: CRLData }) {
            await new Promise<void>((resolve, reject) => {
                const w = chokidar.watch(folder, options);

                w.on("unlink", (filename: string, stat?: fs.Stats) => {
                    filename;
                    stat;
                    // CRL never removed
                });
                w.on("add", (filename: string, stat?: fs.Stats) => {
                    stat;
                    this._on_crl_file_added(index, filename);
                });
                w.on("change", (path: string, stat?: fs.Stats) => {
                    debugLog("change in folder ", folder, path, stat);
                });
                this._watchers.push(w as any);
                w.on("ready", () => {
                    resolve();
                });
            });
        }

        async function _walkAllFiles(this: CertificateManager, folder: string, index: { [key: string]: Entry }) {
            const w = chokidar.watch(folder, options);
            w.on("unlink", (filename: string, stat?: fs.Stats) => {
                stat;
                debugLog(chalk.cyan("unlink in folder " + folder), filename);
                const h = this._filenameToHash[filename];
                if (h && index[h]) {
                    delete index[h];
                }
            });
            w.on("add", (filename: string, stat?: fs.Stats) => {
                stat;
                debugLog(chalk.cyan("add in folder " + folder), filename); // stat);
                try {
                    const certificate = readCertificate(filename);
                    const info = exploreCertificate(certificate);
                    const fingerprint = makeFingerprint(certificate);

                    index[fingerprint] = {
                        certificate,
                        filename,
                    };
                    this._filenameToHash[filename] = fingerprint;

                    debugLog(
                        chalk.magenta("CERT"),
                        info.tbsCertificate.subjectFingerPrint,
                        info.tbsCertificate.serialNumber,
                        info.tbsCertificate.extensions?.authorityKeyIdentifier?.authorityCertIssuerFingerPrint,
                    );
                } catch (err) {
                    debugLog("Walk files in folder " + folder + " with file " + filename);
                    debugLog(err);
                }
            });
            w.on("change", (path: string, stat?: fs.Stats) => {
                stat;
                debugLog("change in folder ", folder, path);
            });
            this._watchers.push(w as any);
            await new Promise<void>((resolve, reject) => {
                w.on("ready", () => {
                    debugLog("ready");
                    debugLog(Object.entries(index).map((kv) => (kv[0] as string).substring(0, 10)));
                    resolve();
                });
            });
        }

        const promises: Promise<void>[] = [
            _walkAllFiles.bind(this, this.trustedFolder, this._thumbs.trusted)(),
            _walkAllFiles.bind(this, this.issuersCertFolder, this._thumbs.issuers.certs)(),
            _walkAllFiles.bind(this, this.rejectedFolder, this._thumbs.rejected)(),
            _walkCRLFiles.bind(this, this.crlFolder, this._thumbs.crl)(),
            _walkCRLFiles.bind(this, this.issuersCrlFolder, this._thumbs.issuersCrl)(),
        ];
        await Promise.all(promises);
        await this.waitAndCheckCRLProcessingStatus();
    }

    // make sure that all crls have been processed.
    private async waitAndCheckCRLProcessingStatus(): Promise<void> {
        return new Promise((resolve, reject) => {
            if (this._pending_crl_to_process === 0) {
                setImmediate(resolve);
                return;
            }
            // istanbul ignore next
            if (this._on_crl_process) {
                return reject(new Error("Internal Error"));
            }
            this._on_crl_process = resolve;
        });
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// node-opcua
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2020 - Etienne Rossignon - etienne.rossignon (at) gadz.org
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

import * as assert from "assert";
import * as async from "async";
import * as chalk from "chalk";
import * as chokidar from "chokidar";
import * as fs from "fs";
import * as path from "path";
import * as util from "util";
import { callbackify, promisify, inspect } from "util";

import {
    Certificate,
    CertificateRevocationList,
    CertificateRevocationListInfo,
    convertPEMtoDER,
    DER,
    exploreCertificate,
    exploreCertificateInfo,
    exploreCertificateRevocationList,
    makeSHA1Thumbprint,
    PEM,
    readCertificate,
    readCertificateRevocationList,
    split_der,
    toPem,
    verifyCertificateSignature,
} from "node-opcua-crypto";

import { SubjectOptions } from "../misc/subject";
import { CertificateStatus, ErrorCallback, Filename, KeySize, Thumbprint } from "./common";
import {
    configurationFileSimpleTemplate,
    createCertificateSigningRequest,
    createPrivateKey,
    createSelfSignCertificate,
    CreateSelfSignCertificateParam,
    CreateSelfSignCertificateWithConfigParam,
    debugLog,
    ensure_openssl_installed,
    make_path,
    mkdir,
    setEnv,
} from "./toolbox";

type ReadFileFunc = (
    filename: string,
    encoding: string,
    callback: (err: Error | null, content?: Buffer) => void
) => void;

const fsFileExists = promisify(fs.exists);
const fsWriteFile = promisify(fs.writeFile);
const fsReadFile = promisify(fs.readFile as ReadFileFunc);
const fsRemoveFile = promisify(fs.unlink);

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
    clr: {
        [key: string]: CRLData; // key is subjectFingerPrint of issuer Certificate
    };
    issuersClr: {
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
    dns: any[];
    startDate: Date;
    validity: number;
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
    return stringToShorten.substr(0, 10);
}
function buildIdealCertificateName(certificate: Certificate): string {
    const fingerprint = makeFingerprint(certificate);
    try {
        const commonName = exploreCertificate(certificate).tbsCertificate.subject.commonName || "";
        return commonName + "[" + fingerprint + "]";
    } catch (err) {
        // make be certificate is incorrect !
        return "invalid_certificate_[" + fingerprint + "]";
    }
}
function findMatchingIssuerKey(certificates: Certificate[], wantedIssuerKey: string): Certificate[] {
    const selected = certificates.filter((certificate) => {
        const info = exploreCertificate(certificate);
        return (
            info.tbsCertificate.extensions && info.tbsCertificate.extensions.subjectKeyIdentifier === wantedIssuerKey
        );
    });
    return selected;
}

export class CertificateManager {
    public untrustUnknownCertificate: boolean = true;
    public initialized: boolean = false;
    public folderPoolingInterval = 5000;

    private readonly keySize: KeySize;
    private readonly location: string;
    private readonly _watchers: fs.FSWatcher[] = [];
    private _readCertificatesCalled: boolean = false;
    private readonly _filenameToHash: { [key: string]: string } = {};

    private readonly _thumbs: Thumbs = {
        rejected: {},
        trusted: {},
        issuers: {
            certs: {},
        },
        clr: {},
        issuersClr: {},
    };

    constructor(options: CertificateManagerOptions) {
        options.keySize = options.keySize || 2048;
        assert(options.hasOwnProperty("location"));
        assert(options.hasOwnProperty("keySize"));
        assert(!this.initialized);

        this.location = make_path(options.location, "");
        this.keySize = options.keySize;

        mkdir(options.location);

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
        return path.join(this.rootDir, "own/private/random.rnd");
    }

    /**
     * returns the certificate status trusted/rejected
     * @param certificate
     */
    public async getCertificateStatus(certificate: Buffer): Promise<CertificateStatus>;
    public getCertificateStatus(
        certificate: Buffer,
        callback: (err: Error | null, status?: CertificateStatus) => void
    ): void;
    public getCertificateStatus(certificate: Buffer, ...args: any[]): any {
        const callback = args[0] as (err: Error | null, status?: CertificateStatus) => void;

        this.initialize(() => {
            this._checkRejectedOrTrusted(certificate, (err: Error | null, status?: CertificateStatus) => {
                if (err) {
                    return callback(err);
                }
                if (status === "unknown") {
                    assert(certificate instanceof Buffer);

                    const pem = toPem(certificate, "CERTIFICATE");
                    const fingerprint = makeFingerprint(certificate);
                    const filename = path.join(this.rejectedFolder, buildIdealCertificateName(certificate) + ".pem");
                    fs.writeFile(filename, pem, (err?: Error | null) => {
                        this._thumbs.rejected[fingerprint] = { certificate, filename };

                        if (err) {
                            return callback(err);
                        }
                        status = "rejected";
                        return callback(null, status);
                    });
                    return;
                } else {
                    return callback(null, status);
                }
            });
        });
    }

    public async rejectCertificate(certificate: Certificate): Promise<void>;
    public rejectCertificate(certificate: Certificate, callback: ErrorCallback): void;
    public rejectCertificate(certificate: Certificate, ...args: any[]): any {
        const callback = args[0];
        assert(callback && callback instanceof Function, "expecting callback");
        this._moveCertificate(certificate, "rejected", callback);
    }

    public async trustCertificate(certificate: Certificate): Promise<void>;
    public trustCertificate(certificate: Certificate, callback: ErrorCallback): void;
    public trustCertificate(certificate: Certificate, ...args: any[]): any {
        const callback = args[0];
        assert(callback && callback instanceof Function, "expecting callback");
        this._moveCertificate(certificate, "trusted", callback);
    }

    public get rejectedFolder(): string {
        return path.join(this.rootDir, "rejected");
    }
    public get trustedFolder(): string {
        return path.join(this.rootDir, "trusted/certs");
    }
    public get clrFolder(): string {
        return path.join(this.rootDir, "trusted/clr");
    }
    public get issuersCertFolder(): string {
        return path.join(this.rootDir, "issuers/certs");
    }
    public get issuersClrFolder(): string {
        return path.join(this.rootDir, "issuers/clr");
    }

    public isCertificateTrusted(
        certificate: Certificate,
        callback: (err: Error | null, trustedStatus: string) => void
    ): void;
    public async isCertificateTrusted(certificate: Certificate): Promise<string>;
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
                    buildIdealCertificateName(certificate) + ".pem"
                );
                if (!this.untrustUnknownCertificate) {
                    return "Good";
                }
                // Certificate should be mark as untrusted
                // let's first verify that certificate is valid ,as we don't want to write invalid data
                try {
                    const certificateInfo = exploreCertificateInfo(certificate);
                } catch (err) {
                    return "BadCertificateInvalid";
                }
                debugLog(
                    "certificate has never been seen before and is now rejected (untrusted) ",
                    certificateFilenameInRejected
                );
                await fsWriteFile(certificateFilenameInRejected, toPem(certificate, "CERTIFICATE"));
            }
            return "BadCertificateUntrusted";
        }
    }
    public async _innerVerifyCertificateAsync(
        certificate: Certificate,
        isIssuer: boolean,
        level: number
    ): Promise<VerificationStatus> {
        if (level >= 5) {
            // maximum level of certificate in chain reached !
            return VerificationStatus.BadSecurityChecksFailed;
        }
        const chain = split_der(certificate);
        debugLog("xxx NB CERTIFICATE IN CHAIN = ", chain.length);
        const info = exploreCertificate(chain[0]);

        let hasTrustedIssuer = false;
        // check if certificate is attached to a issuer
        const hasIssuerKey = info.tbsCertificate.extensions?.authorityKeyIdentifier?.keyIdentifier;
        debugLog("xx Cerficate as an Issuer Key", hasIssuerKey);
        // console.log(inspect(info, { depth: 100 }));

        if (hasIssuerKey) {
            const isSelfSigned =
                info.tbsCertificate.extensions?.subjectKeyIdentifier ===
                info.tbsCertificate.extensions?.authorityKeyIdentifier?.keyIdentifier;
            debugLog("xx Cerficate is self-signed ", isSelfSigned);
            if (!isSelfSigned) {
                const issuerCertificate = await this.findIssuerCertificate(chain[0]);
                // console.log("issuer is found", !!issuerCertificate, info.tbsCertificate.extensions.subjectKeyIdentifier, info.tbsCertificate.extensions?.authorityKeyIdentifier?.keyIdentifier);
                if (!issuerCertificate) {
                    // issuer is not found
                    return VerificationStatus.BadSecurityChecksFailed;
                }
                const issuerStatus = await this._innerVerifyCertificateAsync(issuerCertificate, true, level + 1);
                // console.log("            status ", issuerStatus);
                if (issuerStatus === VerificationStatus.BadCertificateRevocationUnknown) {
                    return VerificationStatus.BadCertificateIssuerRevocationUnknown;
                }
                if (issuerStatus === VerificationStatus.BadCertificateTimeInvalid) {
                    return VerificationStatus.BadCertificateIssuerTimeInvalid;
                }
                if (issuerStatus !== VerificationStatus.Good) {
                    return VerificationStatus.BadSecurityChecksFailed;
                }
                // verify that certificate was signed by issuer
                const isCertificateSignatureOK = verifyCertificateSignature(certificate, issuerCertificate);
                if (!isCertificateSignatureOK) {
                    return VerificationStatus.BadSecurityChecksFailed;
                }
                hasTrustedIssuer = true;

                const s = await this.isCertificateRevoked(certificate);
                if (s !== VerificationStatus.Good) {
                    return s;
                }
            } else {
                // verify that certificate was signed by issuer (self in this case)
                const isCertificateSignatureOK = verifyCertificateSignature(certificate, certificate);
                if (!isCertificateSignatureOK) {
                    return VerificationStatus.BadSecurityChecksFailed;
                }
            }
        }

        const status = await this._checkRejectedOrTrusted(certificate);
        if (status === "rejected") {
            return VerificationStatus.BadCertificateUntrusted;
        }

        const c2 = chain[1] ? exploreCertificateInfo(chain[1]) : "non";
        //  console.log(c1);
        //  console.log(c2);

        // Has SoftwareCertificate passed its issue date and has it not expired ?
        // check dates
        const certificateInfo = exploreCertificateInfo(certificate);
        const now = new Date();

        // check that certificate is active
        if (certificateInfo.notBefore.getTime() > now.getTime()) {
            // certificate is not active yet
            debugLog(
                chalk.red("certificate is invalid : certificate is not active yet !") +
                    "  not before date =" +
                    certificateInfo.notBefore
            );
            return VerificationStatus.BadCertificateTimeInvalid;
        }

        //  check that certificate has not expired
        if (certificateInfo.notAfter.getTime() <= now.getTime()) {
            // certificate is obsolete
            debugLog(
                chalk.red("certificate is invalid : certificate has expired !") +
                    " not after date =" +
                    certificateInfo.notAfter
            );
            return VerificationStatus.BadCertificateTimeInvalid;
        }

        // _check_that_certificate_has_not_been_revoked_by_issuer
        // Has SoftwareCertificate has  been revoked by the issuer ?
        // TODO: check if certificate is revoked or not ...
        // BadCertificateRevoked

        // check that issuer certificate has not been revoked by the CA authority
        // is issuer Certificate valid and has not been revoked by the CA that issued it. ?
        // TODO : check validity of issuer certificate
        // BadCertificateIssuerRevoked

        // check that ApplicationDescription matches URI in certificate
        // does the URI specified in the ApplicationDescription  match the URI in the Certificate ?
        // TODO : check ApplicationDescription of issuer certificate
        // return BadCertificateUriInvalid

        if (status === "trusted") {
            return VerificationStatus.Good;
        }
        assert(status === "unknown");
        // return VerificationStatus.BadCertificateUntrusted;
        //  return isIssuer ? VerificationStatus.Good : VerificationStatus.BadCertificateUntrusted;
        return isIssuer
            ? VerificationStatus.Good
            : hasTrustedIssuer
            ? VerificationStatus.Good
            : VerificationStatus.BadCertificateUntrusted;
    }
    public async verifyCertificateAsync(certificate: Certificate): Promise<VerificationStatus> {
        const status1 = await this._innerVerifyCertificateAsync(certificate, false, 0);
        return status1;
    }

    /**
     * Verify certificate validity
     * @method verifyCertificate
     * @param certificate
     */
    public async verifyCertificate(certificate: Certificate): Promise<VerificationStatus>;
    public verifyCertificate(
        certificate: Certificate,
        callback: (err: Error | null, status?: VerificationStatus) => void
    ): void;
    public verifyCertificate(
        certificate: Certificate,
        callback?: (err: Error | null, status?: VerificationStatus) => void
    ): any {
        // Is the  signature on the SoftwareCertificate valid .?
        if (!certificate) {
            // missing certificate
            return callback!(null, VerificationStatus.BadSecurityChecksFailed);
        }
        callbackify(this.verifyCertificateAsync).call(this, certificate, callback!);
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
    public async initialize(): Promise<void>;
    public initialize(callback: (err?: Error) => void): void;
    public initialize(...args: any[]): any {
        const callback = args[0];
        assert(callback && callback instanceof Function);

        if (this.initialized) {
            return callback();
        }
        this.initialized = true;

        const pkiDir = this.location;
        mkdir(pkiDir);
        mkdir(path.join(pkiDir, "own"));
        mkdir(path.join(pkiDir, "own/certs"));
        mkdir(path.join(pkiDir, "own/private"));
        mkdir(path.join(pkiDir, "rejected"));
        mkdir(path.join(pkiDir, "trusted"));
        mkdir(path.join(pkiDir, "trusted/certs"));
        mkdir(path.join(pkiDir, "trusted/clr"));

        mkdir(path.join(pkiDir, "issuers"));
        mkdir(path.join(pkiDir, "issuers/certs")); // contains Trusted CA certificates
        mkdir(path.join(pkiDir, "issuers/clr")); // contains CRL  of revoked CA certificates

        ensure_openssl_installed(() => {
            // if (1 || !fs.existsSync(this.configFile)) {
            //    var data = toolbox.configurationFileTemplate;
            //    data = data.replace(/%%ROOT_FOLDER%%/, toolbox.make_path(pkiDir,"own"));
            //    fs.writeFileSync(this.configFile, data);
            // }
            //

            fs.writeFileSync(this.configFile, configurationFileSimpleTemplate);

            // note : openssl 1.1.1 has a bug that causes a failure if
            // random file cannot be found. (should be fixed in 1.1.1.a)
            // if this issue become important we may have to consider checking that rndFile exists and recreate
            // it if not . this could be achieved with the command :
            //      "openssl rand -writerand ${this.randomFile}"
            //
            // cf: https://github.com/node-opcua/node-opcua/issues/554

            fs.exists(this.privateKey, (exists: boolean) => {
                if (!exists) {
                    debugLog("generating private key ...");
                    setEnv("RANDFILE", this.randomFile);
                    createPrivateKey(this.privateKey, this.keySize, (err?: Error | null) => {
                        if (err) {
                            return callback(err);
                        }
                        this._readCertificates(() => callback());
                    });
                } else {
                    // debugLog("   intialize :  private key already exists ... skipping");
                    this._readCertificates(() => callback());
                }
            });
        });
    }

    public async dispose(): Promise<void> {
        await Promise.all(this._watchers.map((w) => w.close()));
        this._watchers.forEach((w) => w.removeAllListeners());
        this._watchers.splice(0);
    }
    /**
     *
     * create a self-signed certificate for the CertificateManager private key
     *
     */
    public async createSelfSignedCertificate(params: CreateSelfSignCertificateParam1): Promise<void>;
    public createSelfSignedCertificate(params: CreateSelfSignCertificateParam1, callback: ErrorCallback): void;
    public createSelfSignedCertificate(params: CreateSelfSignCertificateParam1, ...args: any[]): any {
        const callback = args[0];
        const self = this;
        assert(util.isString(params.applicationUri), "expecting applicationUri");
        if (!fs.existsSync(self.privateKey)) {
            return callback(new Error("Cannot find private key " + self.privateKey));
        }

        let certificateFilename = path.join(self.rootDir, "own/certs/self_signed_certificate.pem");
        certificateFilename = params.outputFile || certificateFilename;

        const _params = (params as any) as CreateSelfSignCertificateWithConfigParam;
        _params.rootDir = self.rootDir;
        _params.configFile = self.configFile;
        _params.privateKey = self.privateKey;

        createSelfSignCertificate(certificateFilename, _params, callback);
    }

    public async createCertificateRequest(params: CreateSelfSignCertificateParam): Promise<Filename>;
    public createCertificateRequest(
        params: CreateSelfSignCertificateParam,
        callback: (err: Error | null, certificateSigningRequestFilename?: string) => void
    ): void;
    public createCertificateRequest(
        params: CreateSelfSignCertificateParam,
        callback?: (err: Error | null, certificateSigningRequestFilename?: string) => void
    ): any {
        assert(params);
        assert(util.isFunction(callback));

        const _params = params as CreateSelfSignCertificateWithConfigParam;
        if (_params.hasOwnProperty("rootDir")) {
            throw new Error("rootDir should not be specified ");
        }
        assert(!_params.rootDir);
        assert(!_params.configFile);
        assert(!_params.privateKey);
        _params.rootDir = this.rootDir;
        _params.configFile = this.configFile;
        _params.privateKey = this.privateKey;

        // compose a file name for the request
        const now = new Date();
        const today = now.toISOString().slice(0, 10) + "_" + now.getTime();
        const certificateSigningRequestFilename = path.join(
            this.rootDir,
            "own/certs",
            "certificate_" + today + ".csr"
        );
        createCertificateSigningRequest(certificateSigningRequestFilename, _params, (err?: Error) => {
            return callback!(err!, certificateSigningRequestFilename);
        });
    }

    public async addIssuer(certificate: DER, validate: boolean = false): Promise<VerificationStatus> {
        if (validate) {
            const status = await this.verifyCertificate(certificate);
            if (status !== VerificationStatus.Good) {
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
        const filename = path.join(
            this.issuersCertFolder,
            "issuer_" + buildIdealCertificateName(certificate) + ".pem"
        );
        await promisify(fs.writeFile)(filename, pemCertificate, "ascii");

        // first time seen, let's save it.
        this._thumbs.issuers.certs[fingerprint] = { certificate, filename };

        return VerificationStatus.Good;
    }

    public async addRevocationList(crl: CertificateRevocationList): Promise<VerificationStatus> {
        try {
            const crlInfo = exploreCertificateRevocationList(crl);
            const key = crlInfo.tbsCertList.issuerFingerprint;
            if (!this._thumbs.issuersClr[key]) {
                this._thumbs.issuersClr[key] = { crls: [], serialNumbers: {} };
            }
            const pemCertificate = toPem(crl, "X509 CRL");
            const filename = path.join(this.issuersClrFolder, "crl_" + buildIdealCertificateName(crl) + ".pem");
            await promisify(fs.writeFile)(filename, pemCertificate, "ascii");

            await this._on_crl_file_added(this._thumbs.issuersClr, filename);

            return VerificationStatus.Good;
        } catch (err) {
            debugLog(err);
            return VerificationStatus.BadSecurityChecksFailed;
        }
    }

    // find the issuer certificate
    public async findIssuerCertificate(certificate: Certificate): Promise<Certificate | null> {
        const certInfo = exploreCertificate(certificate);

        const wantedIssuerKey = certInfo.tbsCertificate.extensions?.authorityKeyIdentifier?.keyIdentifier;
        if (!wantedIssuerKey) {
            // Certificate has no extension 3 ! Too old ...
            debugLog("Certificate has no extension 3");
            return null;
        }
        const issuerCertificates = Object.values(this._thumbs.issuers.certs).map((e) => e.certificate);
        const selectedIssuerCertificates = findMatchingIssuerKey(issuerCertificates, wantedIssuerKey);

        if (selectedIssuerCertificates.length > 0) {
            if (selectedIssuerCertificates.length > 1) {
                // tslint:disable-next-line: no-console
                console.log("Warning more than one certificate exists with subjectKeyIdentifier ", wantedIssuerKey);
            }
            return selectedIssuerCertificates[0] || null;
        }
        // check also in trusted  list
        const trustedCertificates = Object.values(this._thumbs.trusted).map((e) => e.certificate);
        const selectedTrustedCerftifcates = findMatchingIssuerKey(trustedCertificates, wantedIssuerKey);
        if (selectedTrustedCerftifcates.length > 1) {
            // tslint:disable-next-line: no-console
            console.log(
                "Warning more than one certificate exists with subjectKeyIdentifier in trusted certificate ",
                wantedIssuerKey
            );
        }
        return selectedTrustedCerftifcates[0] || null;
    }

    /**
     * @internal
     * @param certificate
     * @param callback
     * @private
     */

    public async _checkRejectedOrTrusted(certificate: Buffer): Promise<CertificateStatus>;
    public _checkRejectedOrTrusted(
        certificate: Buffer,
        callback: (err: Error | null, status?: CertificateStatus) => void
    ): void;
    public _checkRejectedOrTrusted(certificate: Buffer, ...args: any[]): any {
        const callback = args[0] as (err: Error | null, status?: CertificateStatus) => void;
        assert(callback && callback instanceof Function);
        assert(certificate instanceof Buffer);
        const fingerprint = makeFingerprint(certificate);

        debugLog("_checkRejectedOrTrusted fingerprint ", short(fingerprint));

        this._readCertificates((err?: Error) => {
            if (err) {
                return callback(err);
            }
            if (this._thumbs.rejected.hasOwnProperty(fingerprint)) {
                return callback(null, "rejected");
            }
            if (this._thumbs.trusted.hasOwnProperty(fingerprint)) {
                return callback(null, "trusted");
            }
            return callback(null, "unknown");
        });
    }

    private _moveCertificate(certificate: Certificate, newStatus: CertificateStatus, callback: ErrorCallback) {
        // a mutex is cerquested here

        assert(certificate instanceof Buffer);
        const fingerprint = makeFingerprint(certificate);

        this.getCertificateStatus(certificate, (err: Error | null, status?: CertificateStatus) => {
            if (err) {
                return callback(err);
            }
            debugLog("_moveCertificate", fingerprint.substr(0, 10), "from", status, "to", newStatus);
            assert(status === "rejected" || status === "trusted");
            if (status !== newStatus) {
                const certificateSrc = (this._thumbs as any)[status!][fingerprint]?.filename;

                // istanbul ignore net
                if (!certificateSrc) {
                    console.log(" cannot find certificate ", fingerprint.substr(0, 10), " in", this._thumbs, [
                        status!,
                    ]);
                    return callback(new Error("internal"));
                }
                const destFolder =
                    newStatus === "rejected"
                        ? this.rejectedFolder
                        : newStatus === "trusted"
                        ? this.trustedFolder
                        : this.rejectedFolder;
                const certificateDest = path.join(destFolder, path.basename(certificateSrc));

                debugLog("_moveCertificate1", fingerprint.substr(0, 10), "old name", certificateSrc);
                debugLog("_moveCertificate1", fingerprint.substr(0, 10), "new name", certificateDest);
                fs.rename(certificateSrc, certificateDest, (err?: Error | null) => {
                    // const certific = (this._thumbs as any)[status!][thumbprint];
                    delete (this._thumbs as any)[status!][fingerprint];
                    (this._thumbs as any)[newStatus][fingerprint] = {
                        certificate,
                        filename: certificateDest,
                    };
                    // we do not return the error here
                    return callback(/*err*/);
                });
            } else {
                return callback();
            }
        });
    }
    private _findAssociatedCRLs(issuerCertificate: Certificate): CRLData | null {
        const issuerCertificateInfo = exploreCertificate(issuerCertificate);
        const key = issuerCertificateInfo.tbsCertificate.subjectFingerPrint;
        return this._thumbs.issuersClr[key]
            ? this._thumbs.issuersClr[key]
            : this._thumbs.clr[key]
            ? this._thumbs.clr[key]
            : null;
    }

    public async isCertificateRevoked(
        certificate: Certificate,
        issuerCertificate?: Certificate | null
    ): Promise<VerificationStatus> {
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
            certInfo.tbsCertificate.serialNumber ||
            certInfo.tbsCertificate.extensions?.authorityKeyIdentifier?.serial ||
            "";

        const crl2 =
            this._thumbs.clr[
                certInfo.tbsCertificate.extensions?.authorityKeyIdentifier?.authorityCertIssuerFingerPrint!
            ] || null;

        if (crls.serialNumbers[serialNumber] || (crl2 && crl2.serialNumbers[serialNumber])) {
            return VerificationStatus.BadCertificateRevoked;
        }
        return VerificationStatus.Good;
    }

    private async _on_crl_file_added(index: { [key: string]: CRLData }, filename: string) {
        try {


            const crl = await readCertificateRevocationList(filename);
            const crlInfo = exploreCertificateRevocationList(crl);
            debugLog(chalk.cyan("add CRL in folder "), filename); // stat);
            const fingerprint = crlInfo.tbsCertList.issuerFingerprint;
            index[fingerprint] = index[fingerprint] || { crls: [], serialNumbers: {} };
            index[fingerprint].crls.push({ crlInfo, filename });

            const serialNumbers = index[fingerprint].serialNumbers;
            // now inject serial numbers
            for (const revokedCertificate of crlInfo.tbsCertList.revokedCertificates) {
                const serialNumber = revokedCertificate.userCertificate;
                if (!serialNumbers[serialNumber]) {
                    serialNumbers[serialNumber] = revokedCertificate.revocationDate;
                }
            }
            debugLog(chalk.cyan("CRL"), fingerprint, Object.keys(serialNumbers)); // stat);
        } catch (err) {
            console.log("CRL filename error =", filename);
            console.log(err);
        }

    }
    private _readCertificates(callback: (err?: Error) => void) {
        if (this._readCertificatesCalled) {
            return callback();
        }
        this._readCertificatesCalled = true;

        function _walkCRLFiles(
            this: CertificateManager,
            folder: string,
            index: { [key: string]: CRLData },
            _innerCallback: (err?: Error) => void
        ) {
            

            const w = chokidar.watch(folder, {
                usePolling: true,
                interval: Math.min(10 * 60 * 1000, Math.max(100, this.folderPoolingInterval)),
                persistent: false,
                awaitWriteFinish: {
                    stabilityThreshold: 2000,
                    pollInterval: 600,
                },
            });
            
            w.on("unlink", (filename: string, stat?: fs.Stats) => {
                // CRL never removed
            });
            w.on("add", async (filename: string, stat?: fs.Stats) => {
                this._on_crl_file_added(index, filename);
            });
            w.on("change", (path: string, stat?: fs.Stats) => {
                debugLog("change in folder ", folder, path, stat);
            });
            this._watchers.push(w);
            w.on("ready", () => {
                _innerCallback();
                debugLog("ready");
                debugLog(Object.entries(index).map((kv) => (kv[0] as string).substr(0, 10)));
            });
        }

        function _walkAllFiles(
            this: CertificateManager,
            folder: string,
            index: { [key: string]: Entry },
            _innerCallback: (err?: Error) => void
        ) {
            const w = chokidar.watch(folder, {
                usePolling: true,
                interval: Math.min(10 * 60 * 1000, Math.max(100, this.folderPoolingInterval)),
                persistent: false,
                awaitWriteFinish: {
                    stabilityThreshold: 2000,
                    pollInterval: 600,
                },
            });
            w.on("unlink", (filename: string, stat?: fs.Stats) => {
                debugLog(chalk.cyan("unlink in folder " + folder), filename);
                const h = this._filenameToHash[filename];
                if (h && index[h]) {
                    delete index[h];
                }
            });
            w.on("add", (filename: string, stat?: fs.Stats) => {
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
                        info.tbsCertificate.extensions?.authorityKeyIdentifier?.authorityCertIssuerFingerPrint
                    );
                }
                catch(err) {
                    console.log("Walk files in folder " + folder + " with file " + filename);
                    console.log(err);
                }
            });
            w.on("change", (path: string, stat?: fs.Stats) => {
                debugLog("change in folder ", folder, path);
            });
            this._watchers.push(w);
            w.on("ready", () => {
                _innerCallback();
                debugLog("ready");
                debugLog(Object.entries(index).map((kv) => (kv[0] as string).substr(0, 10)));
            });
        }
        async.parallel(
            [
                _walkAllFiles.bind(this, this.trustedFolder, this._thumbs.trusted),
                _walkAllFiles.bind(this, this.issuersCertFolder, this._thumbs.issuers.certs),
                _walkAllFiles.bind(this, this.rejectedFolder, this._thumbs.rejected),
                _walkCRLFiles.bind(this, this.clrFolder, this._thumbs.clr),
                _walkCRLFiles.bind(this, this.issuersClrFolder, this._thumbs.issuersClr),
            ],
            (err) => callback(err!)
        );
    }
}

// tslint:disable:no-var-requires
// tslint:disable:max-line-length
const thenify = require("thenify");
const opts = { multiArgs: false };
CertificateManager.prototype.rejectCertificate = thenify.withCallback(
    CertificateManager.prototype.rejectCertificate,
    opts
);
CertificateManager.prototype.trustCertificate = thenify.withCallback(
    CertificateManager.prototype.trustCertificate,
    opts
);
CertificateManager.prototype.createSelfSignedCertificate = thenify.withCallback(
    CertificateManager.prototype.createSelfSignedCertificate,
    opts
);
CertificateManager.prototype.createCertificateRequest = thenify.withCallback(
    CertificateManager.prototype.createCertificateRequest,
    opts
);
CertificateManager.prototype.initialize = thenify.withCallback(CertificateManager.prototype.initialize, opts);
CertificateManager.prototype.getCertificateStatus = thenify.withCallback(
    CertificateManager.prototype.getCertificateStatus,
    opts
);
CertificateManager.prototype._checkRejectedOrTrusted = thenify.withCallback(
    CertificateManager.prototype._checkRejectedOrTrusted,
    opts
);
CertificateManager.prototype.verifyCertificate = thenify.withCallback(
    CertificateManager.prototype.verifyCertificate,
    opts
);
CertificateManager.prototype.isCertificateTrusted = thenify.withCallback(
    callbackify(CertificateManager.prototype.isCertificateTrusted),
    opts
);

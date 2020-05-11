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
import * as util from "util";
import * as fs from "fs";
import * as path from "path";
import * as _ from "underscore";
import { callbackify, promisify } from "util";

import { Certificate, exploreCertificateInfo, makeSHA1Thumbprint, readCertificate, toPem, split_der, PEM, DER, exploreCertificate, convertPEMtoDER } from "node-opcua-crypto";

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
    setEnv
} from "./toolbox";

import { SubjectOptions } from "../misc/subject";
import { CertificateStatus, ErrorCallback, Filename, KeySize, Thumbprint } from "./common";

type ReadFileFunc = (
    filename: string, encoding: string,
    callback: (err: Error | null, content?: Buffer) => void) => void;

const fsFileExists = promisify(fs.exists);
const fsWriteFile = promisify(fs.writeFile);
const fsReadFile = promisify(fs.readFile as ReadFileFunc);
const fsRemoveFile = promisify(fs.unlink);

// tslint:disable-next-line:no-var-requires
const walk = require("walk");

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


export type VerificationStatus =

    /** The certificate provided as a parameter is not valid. */
    "BadCertificateInvalid" |
    /** An error occurred verifying security. */
    "BadSecurityChecksFailed" |
    /** The certificate does not meet the requirements of the security policy. */
    "BadCertificatePolicyCheckFailed" |
    /** The certificate has expired or is not yet valid. */
    "BadCertificateTimeInvalid" |
    /** An issuer certificate has expired or is not yet valid. */
    "BadCertificateIssuerTimeInvalid" |
    /** The HostName used to connect to a server does not match a HostName in the certificate. */
    "BadCertificateHostNameInvalid" |
    /** The URI specified in the ApplicationDescription does not match the URI in the certificate. */
    "BadCertificateUriInvalid" |
    /** The certificate may not be used for the requested operation. */
    "BadCertificateUseNotAllowed" |
    /** The issuer certificate may not be used for the requested operation. */
    "BadCertificateIssuerUseNotAllowed" |
    /** The certificate is not trusted. */
    "BadCertificateUntrusted" |
    /** It was not possible to determine if the certificate has been revoked. */
    "BadCertificateRevocationUnknown" |
    /** It was not possible to determine if the issuer certificate has been revoked. */
    "BadCertificateIssuerRevocationUnknown" |
    /** The certificate has been revoked. */
    "BadCertificateRevoked" |
    /** The issuer certificate has been revoked. */
    "BadCertificateIssuerRevoked" |
    /** The certificate chain is incomplete. */
    "BadCertificateChainIncomplete" |

    /** User does not have permission to perform the requested operation. */
    "BadSecurityChecksFailed" |
    "Good";


export class CertificateManager {

    public untrustUnknownCertificate: boolean = true;

    private readonly keySize: KeySize;
    private readonly location: string;
    private readonly _thumbs: {
        rejected: { [key: string]: Certificate },
        trusted: { [key: string]: Certificate },
        issuers: {
            certs: { [key: string]: Certificate }
        }
    };

    constructor(options: CertificateManagerOptions) {
        options.keySize = options.keySize || 2048;
        assert(options.hasOwnProperty("location"));
        assert(options.hasOwnProperty("keySize"));

        this.location = make_path(options.location, "");
        this.keySize = options.keySize;

        mkdir(options.location);

        // istanbul ignore next
        if (!fs.existsSync(this.location)) {
            throw new Error("CertificateManager cannot access location " + this.location);
        }
        this._thumbs = {
            rejected: {},
            trusted: {},
            issuers: {
                certs: {}
            }
        };
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
    public getCertificateStatus(certificate: Buffer,
        callback: (err: Error | null, status?: CertificateStatus) => void): void;
    public getCertificateStatus(certificate: Buffer, ...args: any[]): any {

        const callback = args[0] as (err: Error | null, status?: CertificateStatus) => void;

        this.initialize(() => {

            this._checkRejectedOrTrusted(
                certificate,
                (err: Error | null, status?: CertificateStatus) => {
                    if (err) {
                        return callback(err);
                    }
                    if (status === "unknown") {
                        assert(certificate instanceof Buffer);
                        const thumbprint = makeSHA1Thumbprint(certificate).toString("hex");
                        const certificateName = path.join(this.rootDir, "rejected", thumbprint + ".pem");

                        const pem = toPem(certificate, "CERTIFICATE");
                        fs.writeFile(certificateName, pem, (err?: Error | null) => {
                            if (err) {
                                return callback(err);
                            }
                            status = "rejected";
                            return callback(null, status);
                        });
                        return;
                    }
                    return callback(null, status);
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
        return path.join(this.rootDir, "trusted");
    }
    public get issuersCertFolder(): string {
        return path.join(this.rootDir, "issuers/certs");
    }

    public isCertificateTrusted(
        certificate: Certificate,
        callback: (err: Error | null, trustedStatus: string
        ) => void): void;
    public async isCertificateTrusted(certificate: Certificate): Promise<string>;
    public async isCertificateTrusted(certificate: Certificate): Promise<string> {

        const thumbprint = makeSHA1Thumbprint(certificate);

        const certificateFilenameInTrusted = path.join(this.trustedFolder, thumbprint.toString("hex") + ".pem");

        const fileExistInTrustedFolder: boolean = await fsFileExists(certificateFilenameInTrusted);

        if (fileExistInTrustedFolder) {
            const content: Certificate = await readCertificate(certificateFilenameInTrusted);
            if (content.toString("base64") !== certificate.toString("base64")) {
                return "BadCertificateInvalid";
            }
            return "Good";
        } else {
            const certificateFilenameInRejected = path.join(this.rejectedFolder, thumbprint.toString("hex") + ".pem");
            if (!await fsFileExists(certificateFilenameInRejected)) {

                if (this.untrustUnknownCertificate) {
                    // Certificate should be mark as untrusted

                    // let's first verify that certificate is valid ,as we don't want to write invalid data
                    try {
                        const certificateInfo = exploreCertificateInfo(certificate);
                    } catch (err) {
                        return "BadCertificateInvalid";
                    }
                    await fsWriteFile(certificateFilenameInRejected, toPem(certificate, "CERTIFICATE"));
                } else {

                    return "Good";
                }
            }
            debugLog("certificate has never been seen before and is rejected untrusted ", certificateFilenameInRejected);
            return "BadCertificateUntrusted";
        }
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
            return callback!(null, "BadSecurityChecksFailed");
        }

        const chain = split_der(certificate);
        console.log("xxx NB CERTIFICATE IN CHAIN = ", chain.length);
        const c1 = exploreCertificateInfo(chain[0]);
        const c2 = exploreCertificateInfo(chain[1]);
        console.log(c1);
        console.log(c2);

        // Has SoftwareCertificate passed its issue date and has it not expired ?
        // check dates
        const certificateInfo = exploreCertificateInfo(certificate);
        const now = new Date();

        // check that certificate is active
        if (certificateInfo.notBefore.getTime() > now.getTime()) {
            // certificate is not active yet
            debugLog(chalk.red("certificate is invalid : certificate is not active yet !") +
                "  not before date =" + certificateInfo.notBefore);
            return callback!(null, "BadCertificateTimeInvalid");
        }

        //  check that certificate has not expired
        if (certificateInfo.notAfter.getTime() <= now.getTime()) {
            // certificate is obsolete
            debugLog(chalk.red("certificate is invalid : certificate has expired !")
                + " not after date =" + certificateInfo.notAfter);
            return callback!(null, "BadCertificateTimeInvalid");
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

        this._checkRejectedOrTrusted(certificate, (err?: Error | null, status?: CertificateStatus) => {

            // istanbul ignore next
            if (err) {
                return callback!(err);
            }
            if (status === "rejected") {
                return callback!(null, "BadCertificateUntrusted");
            } else if (status === "trusted") {
                return callback!(null, "Good"); // OK
            }
            assert(status === "unknown");
            return callback!(null, "BadCertificateUntrusted");
        });
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

        const pkiDir = this.location;
        mkdir(pkiDir);
        mkdir(path.join(pkiDir, "own"));
        mkdir(path.join(pkiDir, "own/certs"));
        mkdir(path.join(pkiDir, "own/private"));
        mkdir(path.join(pkiDir, "trusted"));
        mkdir(path.join(pkiDir, "rejected"));

        mkdir(path.join(pkiDir, "issuers"));
        mkdir(path.join(pkiDir, "issuers/certs")); // contains Trusted CA certificates
        mkdir(path.join(pkiDir, "issuers/crl"));// contains CRL  of revoked CA certificates

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
                        callback(err);
                    });
                } else {
                    debugLog("private key already exists ... skipping");
                    callback();
                }
            });
        });
    }

    /**
     *
     * create a self-signed certificate for the CertificateManager private key
     *
     */
    public async createSelfSignedCertificate(
        params: CreateSelfSignCertificateParam1,
    ): Promise<void>;
    public createSelfSignedCertificate(
        params: CreateSelfSignCertificateParam1,
        callback: ErrorCallback
    ): void;
    public createSelfSignedCertificate(
        params: CreateSelfSignCertificateParam1,
        ...args: any[]
    ): any {
        const callback = args[0];
        const self = this;
        assert(_.isString(params.applicationUri), "expecting applicationUri");
        if (!fs.existsSync(self.privateKey)) {
            return callback(new Error("Cannot find private key " + self.privateKey));
        }

        let certificateFilename = path.join(self.rootDir, "own/certs/self_signed_certificate.pem");
        certificateFilename = params.outputFile || certificateFilename;

        const _params = params as any as CreateSelfSignCertificateWithConfigParam;
        _params.rootDir = self.rootDir;
        _params.configFile = self.configFile;
        _params.privateKey = self.privateKey;

        createSelfSignCertificate(certificateFilename, _params, callback);
    }

    public async createCertificateRequest(
        params: CreateSelfSignCertificateParam,
    ): Promise<Filename>;
    public createCertificateRequest(
        params: CreateSelfSignCertificateParam,
        callback: (err: Error | null, certificateSigningRequestFilename?: string) => void
    ): void;
    public createCertificateRequest(
        params: CreateSelfSignCertificateParam,
        callback?: (err: Error | null, certificateSigningRequestFilename?: string) => void
    ): any {

        assert(params);
        assert(_.isFunction(callback));

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
            "own/certs", "certificate_" + today + ".csr");
        createCertificateSigningRequest(
            certificateSigningRequestFilename,
            _params,
            (err?: Error) => {
                return callback!(err!, certificateSigningRequestFilename);
            });
    }


    public async addIssuer(certificate: DER, validate: boolean = false): Promise<VerificationStatus> {

        if (validate) {
            const status = await this.verifyCertificate(certificate);
            if (status !== "Good") {
                return status;
            }
        }
        const pemCertificate = toPem(certificate, "CERTIFICATE");
        const thumbprintHex = makeSHA1Thumbprint(certificate).toString("hex");
        this._thumbs.issuers.certs[thumbprintHex] = certificate;

        const filename = path.join(this.issuersCertFolder, thumbprintHex + ".crt");

        await promisify(fs.writeFile)(filename, pemCertificate, "ascii");
        return "Good";
    }

    // find the issuer certificate
    public async findIssuerCertificate(certificate: Certificate): Promise<Certificate | null> {

        const certInfo = exploreCertificate(certificate);
        if (!certInfo.tbsCertificate.extensions || !certInfo.tbsCertificate.extensions.authorityKeyIdentifier) {
            // Certificate has no extension 3 ! Too old ...
            return null;
        }
        const wantedIssuerKey = certInfo.tbsCertificate.extensions.authorityKeyIdentifier.keyIdentifier;
        const issuerCertificates = Object.values(this._thumbs.issuers.certs);

        const selectedIssuerCerftifcate = issuerCertificates.filter(issuerCertificate => {
            const info = exploreCertificate(issuerCertificate);
            return (info.tbsCertificate.extensions && info.tbsCertificate.extensions.subjectKeyIdentifier === wantedIssuerKey);
        });

        if (selectedIssuerCerftifcate.length > 1) {
            // tslint:disable-next-line: no-console
            console.log("Warning more than one certificate exists with subjectKeyIdentifier ", wantedIssuerKey);
        }
        return selectedIssuerCerftifcate[0] || null;
    }

    /**
     * @internal
     * @param certificate
     * @param callback
     * @private
     */

    public async _checkRejectedOrTrusted(certificate: Buffer): Promise<CertificateStatus>;
    public _checkRejectedOrTrusted(certificate: Buffer, callback: (err: Error | null, status?: CertificateStatus) => void): void;
    public _checkRejectedOrTrusted(certificate: Buffer, ...args: any[]): any {

        const callback = args[0] as (err: Error | null, status?: CertificateStatus) => void;
        assert(callback && callback instanceof Function);
        assert(certificate instanceof Buffer);
        const thumbprint = makeSHA1Thumbprint(certificate).toString("hex");

        debugLog("thumbprint ", thumbprint);

        this._readCertificates((err?: Error) => {
            if (err) {
                return callback(err);
            }
            if (this._thumbs.rejected.hasOwnProperty(thumbprint)) {
                return callback(null, "rejected");
            }
            if (this._thumbs.trusted.hasOwnProperty(thumbprint)) {
                return callback(null, "trusted");
            }
            return callback(null, "unknown");
        });

    }

    private _moveCertificate(
        certificate: Certificate,
        newStatus: CertificateStatus,
        callback: ErrorCallback
    ) {

        assert(certificate instanceof Buffer);
        const thumbprint = makeSHA1Thumbprint(certificate).toString("hex");

        this.getCertificateStatus(certificate, (err: Error | null, status?: CertificateStatus) => {
            if (err) {
                return callback(err);
            }

            if (status !== newStatus) {
                const certificateSrc = path.join(this.rootDir, status!, thumbprint + ".pem");
                const certificateDest = path.join(this.rootDir, newStatus, thumbprint + ".pem");

                fs.rename(certificateSrc, certificateDest, (err?: Error | null) => {
                    assert(status === "rejected" || status === "trusted");
                    const cert = (this._thumbs as any)[status!][thumbprint];
                    delete (this._thumbs as any)[status!][thumbprint];
                    (this._thumbs as any)[newStatus][thumbprint] = cert;
                    return callback(err);
                });

            } else {
                return callback();
            }
        });
    }

    private _readCertificates(callback: (err?: Error) => void) {


        function _f(folder: string, index: { [key: string]: Certificate }, callback: (err?: Error) => void) {

            // empty list first
            Object.keys(index).forEach((key) => delete index[key]);

            const walker = walk.walk(folder, { followLinks: false });

            walker.on("file", (root: string, stat: any, next: () => void) => {

                const filename = path.join(root, stat.name);
                try {
                    const certificate = readCertificate(filename);
                    const thumbprint = makeSHA1Thumbprint(certificate).toString("hex");
                    index[thumbprint] = certificate;
                } catch (err) {
                    debugLog("err : ", err.message);
                }
                next();
            });
            walker.on("end", () => {
                return callback();
            });
        }

        async.parallel([
            (callback: (err?: Error) => void) => {
                _f.bind(this, path.join(this.rootDir, "trusted"), this._thumbs.trusted)
                    .call(null, callback);
            },
            (callback: (err?: Error) => void) => {
                _f.bind(this, path.join(this.rootDir, "rejected"), this._thumbs.rejected)
                    .call(null, callback);
            },
            (callback: (err?: Error) => void) => {
                _f.bind(this, path.join(this.rootDir, "issuers/certs"), this._thumbs.issuers.certs)
                    .call(null, callback);
            }
        ], (err) => callback(err!));
    }
}

// tslint:disable:no-var-requires
// tslint:disable:max-line-length
const thenify = require("thenify");
const opts = { multiArgs: false };
CertificateManager.prototype.rejectCertificate = thenify.withCallback(CertificateManager.prototype.rejectCertificate, opts);
CertificateManager.prototype.trustCertificate = thenify.withCallback(CertificateManager.prototype.trustCertificate, opts);
CertificateManager.prototype.createSelfSignedCertificate = thenify.withCallback(CertificateManager.prototype.createSelfSignedCertificate, opts);
CertificateManager.prototype.createCertificateRequest = thenify.withCallback(CertificateManager.prototype.createCertificateRequest, opts);
CertificateManager.prototype.initialize = thenify.withCallback(CertificateManager.prototype.initialize, opts);
CertificateManager.prototype.getCertificateStatus = thenify.withCallback(CertificateManager.prototype.getCertificateStatus, opts);
CertificateManager.prototype._checkRejectedOrTrusted = thenify.withCallback(CertificateManager.prototype._checkRejectedOrTrusted, opts);
CertificateManager.prototype.verifyCertificate = thenify.withCallback(CertificateManager.prototype.verifyCertificate, opts);
CertificateManager.prototype.isCertificateTrusted = thenify.withCallback(callbackify(CertificateManager.prototype.isCertificateTrusted), opts);

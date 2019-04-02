// tslint:disable:no-console
// tslint:disable:no-shadowed-variable

import * as async from "async";
import * as fs from "fs";
import {PrivateKey, readCertificate, split_der} from "node-opcua-crypto";
import * as path from "path";

import should = require("should");
import * as pki from "..";
import {ErrorCallback, execute_openssl, Filename, g_config, Params, x509Date} from "..";
import {beforeTest} from "./helpers";

const _should = should;

describe("Certificate Authority", function() {

    const testData = beforeTest(this);
    let options: any = {};
    before(() => {
        options = {
            keySize: 2048,
            location: path.join(testData.tmpFolder, "CA"),
        };
    });

    it("should read openssl version", (done: ErrorCallback) => {

        execute_openssl("version",
            {cwd: "."},
            (err: Error | null, output?: string) => {
                if (err) {
                    return done(err);
                }
                output = output!.trim();
                g_config.opensslVersion.should.eql(output);
                done(err!);
            });
    });

    it("should create a CertificateAuthority", (done: ErrorCallback) => {

        const ca = new pki.CertificateAuthority(options);
        ca.initialize((err?: Error | null) => {
            done(err);
        });
    });

});

describe("Signing Certificate with Certificate Authority", function() {

    const testData = beforeTest(this);

    let ca: pki.CertificateAuthority;
    let cm: pki.CertificateManager;

    before((done: ErrorCallback) => {

        ca = new pki.CertificateAuthority({
            keySize: 2048,
            location: path.join(testData.tmpFolder, "CA")
        });

        cm = new pki.CertificateManager({
            location: path.join(testData.tmpFolder, "PI")
        });

        async.series([
            (callback: ErrorCallback) => {
                cm.initialize(callback);
            },
            (callback: ErrorCallback) => {
                ca.initialize(callback);
            }
        ], done);
    });

    function createCertificateRequest(
        callback: (err: Error | null, certificateRequest?: string) => void
    ) {

        // let create a certificate request
        const params = {
            applicationUri: "MY:APPLICATION:URI",
            dns: [
                "localhost",
                "my.domain.com"
            ],
            ip: [
                "192.123.145.121"
            ],
            subject: "/CN=MyCommonName",
            // can only be TODAY due to openssl limitation : startDate: new Date(2010,2,2),
            validity: 365 * 7,
        };
        cm.createCertificateRequest(
            params,
            (err: Error | null, certificateSigningRequestFilename?: string) => {
                callback(err, certificateSigningRequestFilename);
            });

    }

    it("T0 - should have a CA Certificate", (done: ErrorCallback) => {
        fs.existsSync(ca.caCertificate).should.eql(true);
        done();
    });

    it("T1 - should have a CA Certificate with a CRL", (done: ErrorCallback) => {
        ca.constructCACertificateWithCRL(() => {
            fs.existsSync(ca.caCertificateWithCrl).should.eql(true);
            done();
        });
    });

    it("T2 - should sign a Certificate Request", (done: ErrorCallback) => {

        const self = {
            certificateRequest: ""
        };

        async.series([

            (callback: ErrorCallback) => {
                // create a Certificate Signing Request
                createCertificateRequest((err: Error | null, certificateSigningRequestFilename?: Filename) => {
                    self.certificateRequest = certificateSigningRequestFilename!;
                    fs.existsSync(self.certificateRequest).should.eql(true);
                    callback(err!);
                });
            },

            (callback: ErrorCallback) => {

                fs.existsSync(self.certificateRequest).should.eql(true);

                const certificateFilename = path.join(testData.tmpFolder, "sample_certificate.pem");

                const params = {
                    applicationUri: "BAD SHOULD BE IN REQUEST",
                    startDate: new Date(2011, 25, 12),
                    validity: 10 * 365
                };

                ca.signCertificateRequest(
                    certificateFilename,
                    self.certificateRequest,
                    params,
                    (err: Error | null, certificate?: Filename) => {
                        fs.existsSync(certificate!).should.eql(true);

                        // Serial Number: 4096 (0x1000)

                        const certificateChain = readCertificate(certificate!);
                        const elements = split_der(certificateChain);
                        elements.length.should.eql(2);
                        // should have 2 x -----BEGIN CERTIFICATE----- in the chain
                        callback(err ? err : undefined);
                    });
            },

            (callback: ErrorCallback) => {
                // should verify that certificate is valid
                // todo
                callback();
            }
        ], done);
    });

    function sign(
        certificateRequest: Filename,
        startDate: Date,
        validity: number,
        callback: (err: Error | null, certfile?: Filename) => void
    ) {

        const a = x509Date(startDate) + "_" + validity;

        fs.existsSync(certificateRequest).should.eql(true,
            "certificate request " + certificateRequest + " must exist");

        const certificateFilename = path.join(testData.tmpFolder, "sample_certificate" + a + ".pem");

        const params = {
            applicationUri: "BAD SHOULD BE IN REQUEST",
            startDate,
            validity
        };

        ca.signCertificateRequest(
            certificateFilename,
            certificateRequest,
            params,
            (err: Error | null, certificate?: Filename) => {

                // xx console.log("Certificate = ",certificate);
                if (!err) {
                    fs.existsSync(certificate!).should.eql(true);
                }
                // Serial Number: 4096 (0x1000)

                // should have 2 x -----BEGIN CERTIFICATE----- in the chain
                callback(err, certificateFilename);

            });
    }

    const now = new Date();
    const lastYear = new Date();
    lastYear.setFullYear(now.getFullYear() - 1);
    const nextYear = (new Date());
    nextYear.setFullYear(now.getFullYear() + 1);
    it("T3 - should create various Certificates signed by the CA authority", (done: ErrorCallback) => {

        let certificateRequest = "";

        async.series([

            (callback: ErrorCallback) => {
                // create a Certificate Signing Request
                createCertificateRequest(
                    (err: Error | null, _certificateRequest?: Filename) => {

                        certificateRequest = _certificateRequest!;
                        fs.existsSync(certificateRequest).should.eql(true,
                            "certificate request " + certificateRequest + " must exist");
                        callback(err!);
                    });
            },
            (callback: ErrorCallback) => {
                sign(certificateRequest, lastYear, 200,
                    (err: Error | null) => callback(err!)); // outdated
            },
            (callback: ErrorCallback) => {
                sign(certificateRequest, lastYear, 10 * 365,  // valid
                    (err: Error | null) => callback(err!));
            },

            (callback: ErrorCallback) => {
                sign(certificateRequest, nextYear, 365,  // not started yet
                    (err: Error | null) => callback(err!));

            }
        ], done);

    });

    it("T4 - should create various self-signed Certificates using the CA", (done: ErrorCallback) => {

        // using a CA to construct self-signed certificates provides the following benefits:
        //    - startDate can be easily specified in the past or the future
        //    - certificate can be revoked ??? to be checked.

        const privateKey = cm.privateKey;
        const certificate = path.join(testData.tmpFolder, "sample_self_signed_certificate.pem");

        fs.existsSync(certificate).should.eql(false);
        ca.createSelfSignedCertificate(
            certificate,
            privateKey,
            {
                applicationUri: "SomeUri"
            },
            (err?: Error | null) => {
                fs.existsSync(certificate).should.eql(true);
                done(err!);
            });
    });

    /**
     *
     * @param certificate  {String} certificate to create
     * @param privateKey
     * @param callback
     */
    function createSelfSignedCertificate(
        certificate: Filename,
        privateKey: Filename,
        callback: (err: Error | null, certificate?: Filename) => void
    ) {

        const startDate = new Date();
        const validity = 1000;
        const params: Params = {
            applicationUri: "BAD SHOULD BE IN REQUEST",
            startDate,
            validity
        };
        ca.createSelfSignedCertificate(
            certificate,
            privateKey,
            params,
            (err?: Error | null) => {
                console.log("signed_certificate = signed_certificate", certificate);
                callback(err!, certificate);
            });
    }

    it("T5 - should revoke a self-signed certificate", (done: ErrorCallback) => {

        const privateKey = cm.privateKey;
        const certificate = path.join(testData.tmpFolder, "certificate_to_be_revoked1.pem");

        const tasks = [

            (callback: ErrorCallback) => {
                createSelfSignedCertificate(certificate, privateKey, (err: Error | null) => {
                    fs.existsSync(certificate).should.eql(true);
                    callback(err!);
                });
            },

            (callback: ErrorCallback) => {
                ca.revokeCertificate(certificate, {}, callback);
            }
        ];
        async.series(tasks, done);
    });

    function createCertificateFromCA(
        callback: (err: Error | null, certificate?: Filename) => void
    ) {
        let certificateRequest = "";
        let signedCertificate = "";
        async.series([
            (callback: ErrorCallback) => {
                // create a Certificate Signing Request
                createCertificateRequest((err: Error | null, _certificateRequest?: Filename) => {
                    certificateRequest = _certificateRequest!;
                    callback(err!);
                });
            },
            (callback: ErrorCallback) => {
                sign(
                    certificateRequest,
                    lastYear,
                    10 * 365 + 10,
                    (err: Error | null, _signedCertificate?: string) => {
                        signedCertificate = _signedCertificate!;
                        callback(err!);
                    });
            }
        ], (err?: Error | null) => {
            callback(err!, signedCertificate);
        });
    }

    it("T6 - should revoke a certificate emitted by the CA", (done: ErrorCallback) => {

        let certificate = "";
        const tasks = [

            (callback: ErrorCallback) => {
                createCertificateFromCA((err: Error | null, _certificate?: Filename) => {
                    certificate = _certificate!;
                    fs.existsSync(certificate).should.eql(true);
                    callback(err!);
                });
            },

            (callback: ErrorCallback) => {
                ca.revokeCertificate(certificate, {}, callback);
            }
        ];
        async.series(tasks, done);
    });

});

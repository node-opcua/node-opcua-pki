// tslint:disable:variable-name
// tslint:disable:no-shadowed-variable
Error.stackTraceLimit = Infinity;
import * as async from "async";
import * as fs from "fs";
import {Certificate, readCertificate} from "node-opcua-crypto";
import * as path from "path";

import should = require("should");
import * as pki from "../lib/index";
import {CertificateAuthorityOptions, ErrorCallback, Filename, KeySize, Params} from "../lib/index";

// ------------------------------------------------- some useful dates
function get_offset_date(date: Date, nb_days: number): Date {
    const d = new Date(date.getTime());
    d.setDate(d.getDate() + nb_days);
    return d;
}

const today = new Date();
const lastYear = get_offset_date(today, -365);
const nextYear = get_offset_date(today, 365);
const yesterday = get_offset_date(today, -1);

describe("test certificate validation", function() {

    let certificate_out_of_date: Filename;
    let certificate_not_yet_active: Filename;
    let certificate_valid: Filename;
    let certificate_valid_untrusted: Filename;

    function prepare_test(done: ErrorCallback) {

        const optionsCA: CertificateAuthorityOptions = {
            keySize: 2048 as KeySize,
            location: path.join(test.tmpFolder, "TEST_CA")
        };

        certificateAuthority = new pki.CertificateAuthority(optionsCA);

        const optionsPKI = {location: path.join(test.tmpFolder, "TEST_PKI")};
        certificateManager = new pki.CertificateManager(optionsPKI);

        async.series([

            (callback: ErrorCallback) => {
                certificateAuthority.initialize(callback);
            },
            (callback: ErrorCallback) => {
                certificateManager.initialize(callback);
            },
            (callback: ErrorCallback) => {
                certificate_out_of_date = path.join(test.tmpFolder, "certificate_out_of_date.pem");
                createCertificate(certificate_out_of_date,
                    {applicationUri: "SOMEURI", startDate: lastYear, validity: 300}, callback);
            },
            (callback: ErrorCallback) => {
                certificate_not_yet_active = path.join(test.tmpFolder, "certificate_notyetactive.pem");
                createCertificate(certificate_not_yet_active,
                    {applicationUri: "SOMEURI", startDate: nextYear, validity: 10000}, callback);
            },
            (callback: ErrorCallback) => {
                certificate_valid = path.join(test.tmpFolder, "certificate_valid.pem");
                createCertificate(certificate_valid,
                    {applicationUri: "SOMEURI", startDate: yesterday, validity: 10}, callback);
            },
            (callback: ErrorCallback) => {
                certificate_valid_untrusted = path.join(test.tmpFolder, "certificate_valid_untrusted.pem");
                createCertificate(certificate_valid_untrusted,
                    {applicationUri: "SOMEURI", startDate: yesterday, validity: 10}, callback);
            },
            /*
            (callback: ErrorCallback) => {
                certificate_valid_revoked = path.join(test.tmpFolder, "certificate_valid_revoked.pem");
                createCertificate(certificate_valid_revoked,
                     {applicationUri: "SOMEURI", startDate: yesterday, validity: 10 },callback)
            },
            (callback: ErrorCallback) => {
                certificateAuthority.revokeCertificate(certificate_valid_revoked,{reason: "keyCompromise"},callback);
            },
            (callback: ErrorCallback) => {
                const ca_with_crl_filename = certificateAuthority.caCertificateWithCrl;
                fs.existsSync(ca_with_crl).should.eql(true);
                const ca_with_crl = crypto_utils.readKeyPem(ca_with_crl_filename);
                certificateManager.setCACertificate(ca_with_crl);
                // simulate certificateManager receiving Certificate Revocation list
                callback();
            }
            */

        ], done);
    }

    const test = require("./helpers").beforeTest(this, prepare_test);

    let certificateManager: pki.CertificateManager;
    let certificateAuthority: pki.CertificateAuthority;

    /**
     * @method createCertificate
     * @param params
     * @param params.applicationUri {String}
     * @param params.dns            {String[]}
     * @param callback
     */
    function createCertificate(
        certificate: Filename,
        params: Params,
        callback: (err?: Error | null) => void
    ) {

        let theCertificateRequest: string;
        async.series([

            (callback: ErrorCallback) => {
                // lets create
                certificateManager.createCertificateRequest(
                    params,
                    (err: Error | null, csr_file?: Filename) => {
                        if (err) {
                            return callback(err);
                        }
                        theCertificateRequest = csr_file!;
                        callback();
                    });
            },
            (callback: ErrorCallback) => {

                fs.existsSync(certificate).should.eql(false);
                fs.existsSync(theCertificateRequest).should.eql(true);
                certificateAuthority.signCertificateRequest(
                    certificate,
                    theCertificateRequest,
                    params,
                    (err: Error | null) => {
                        fs.existsSync(theCertificateRequest).should.eql(true);
                        fs.existsSync(certificate).should.eql(true);
                        callback(err!);
                    });
            }
        ], callback);
    }

    describe("should verify ", () => {

        let localCertificateManager: pki.CertificateManager;

        let cert1: Certificate;
        let cert2: Certificate;
        let cert3: Certificate;
        let certificate_valid_untrusted_A: Certificate;

        before((done: ErrorCallback) => {
            const optionsPKI2 = {location: path.join(test.tmpFolder, "TEST_PKI2")};
            localCertificateManager = new pki.CertificateManager(optionsPKI2);
            // get certificate

            cert1 = readCertificate(certificate_out_of_date);
            cert2 = readCertificate(certificate_not_yet_active);
            cert3 = readCertificate(certificate_valid);
            certificate_valid_untrusted_A = readCertificate(certificate_valid_untrusted);

            async.series([
                (callback: ErrorCallback) => {
                    localCertificateManager.trustCertificate(cert3, callback);
                },
                (callback: ErrorCallback) => {
                    localCertificateManager.rejectCertificate(certificate_valid_untrusted_A, callback);
                }
            ], done);
        });

        it("should detect null certificate", (done: ErrorCallback) => {
            localCertificateManager.verifyCertificate(
                null! as Buffer,
                (err?: Error | null) => {
                    should.exist(err);
                    err!.message.should.match("BadSecurityChecksFailed");
                    done();
                });
        });

        it("should detect out of date certificate", (done: ErrorCallback) => {
            localCertificateManager.verifyCertificate(cert1, (err?: Error | null) => {
                err!.message.should.match("BadCertificateTimeInvalid");
                done();
            });
        });

        it("should detect 'not active yet' certificate", (done: ErrorCallback) => {
            localCertificateManager.verifyCertificate(cert2, (err?: Error | null) => {
                err!.message.should.match("BadCertificateTimeInvalid");
                done();
            });
        });

        it("should detect a valid certificate", (done: ErrorCallback) => {
            localCertificateManager.verifyCertificate(cert3, (err?: Error | null) => {
                should(err).eql(null);
                done();
            });
        });

        it("should detect untrusted certificate", (done: ErrorCallback) => {
            localCertificateManager.verifyCertificate(certificate_valid_untrusted_A, (err?: Error | null) => {
                err!.message.should.match("BadCertificateUntrusted");
                done();
            });
        });
    });
});

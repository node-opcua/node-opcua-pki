Error.stackTraceLimit = Infinity;
// tslint:disable:variable-name
// tslint:disable:no-shadowed-variable
import * as async from "async";
import * as fs from "fs";
import * as path from "path";
import {promisify} from "util";

import {beforeTest, grep} from "./helpers";

import should = require("should");
import * as pki from "..";
import {
    CertificateStatus,
    dumpCertificate,
    ErrorCallback,
    execute_openssl,
    Filename,
    g_config,
    generateStaticConfig,
    make_path,
    processAltNames,
    quote
} from "../lib";

const _should = should;

const q = quote;
const n = make_path;

describe("CertificateManager", function() {

    this.timeout(400000);

    const test = beforeTest(this);

    it("should create a certificateManager", (done: ErrorCallback) => {

        const options = {
            location: path.join(test.tmpFolder, "PKI")
        };

        const cm = new pki.CertificateManager(options);

        cm.initialize((err?: Error) => {

            fs.existsSync(path.join(options.location)).should.eql(true);
            fs.existsSync(path.join(options.location, "trusted")).should.eql(true);
            fs.existsSync(path.join(options.location, "rejected")).should.eql(true);
            fs.existsSync(path.join(options.location, "own")).should.eql(true);
            fs.existsSync(path.join(options.location, "own/certs")).should.eql(true);
            fs.existsSync(path.join(options.location, "own/private")).should.eql(true);

            fs.existsSync(path.join(options.location, "own/openssl.cnf")).should.eql(true);
            fs.existsSync(path.join(options.location, "own/private/private_key.pem")).should.eql(true);

            const data = fs.readFileSync(path.join(options.location, "own/openssl.cnf"), "ascii");

            // config file must have a distinguish name section
            grep(data, /distinguished_name/).should.match(/distinguished_name/);

            done(err);
        });
    });

    it("should create its own self-signed certificate", (done: ErrorCallback) => {

        function get_days(date1: Date, date2: Date): number {
            const ms_in_one_day = 24 * 3600000;
            const diff = date1.getTime() - date2.getTime();
            return Math.round(diff / ms_in_one_day);
        }

        const options = {
            location: path.join(test.tmpFolder, "PKI1")
        };

        const cm = new pki.CertificateManager(options);

        cm.initialize((err?: Error) => {
            if (err) {
                return done(err);
            }
            const now = new Date();
            const endDate = new Date(now.getFullYear() + 7, 10, 10);
            const duration = get_days(endDate, now);

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
                validity: duration,
            };

            cm.createSelfSignedCertificate(params, (err?: Error | null) => {

                if (err) {
                    return done(err);
                }

                const expectedCertificate = path.join(options.location, "own/certs/self_signed_certificate.pem");
                fs.existsSync(expectedCertificate).should.eql(true);

                dumpCertificate(expectedCertificate, (err: Error | null, data?: string) => {

                    if (err || !data) {
                        return done(err || new Error("No Data"));
                    }
                    fs.writeFileSync(path.join(test.tmpFolder, "dump_cert1.txt"), data!);

                    grep(data, /URI/).should.match(/URI:MY:APPLICATION:URI/);
                    grep(data, /DNS/).should.match(/DNS:localhost/);
                    grep(data, /DNS/).should.match(/DNS:my.domain.com/);

                    if (g_config.opensslVersion.match(/1.0.2/)) {
                        // note openssl version 1.0.1 does support sha256 signature
                        grep(data, /Signature Algorithm/).should.match(/Signature Algorithm: sha256WithRSAEncryption/);
                    }
                    grep(data, /SelfSigned/).should.match(/SelfSigned/);

                    const y = (new Date()).getFullYear();
                    grep(data, /Not Before/).should.match(new RegExp(y.toString() + " GMT"));
                    grep(data, /Not After/).should.match(new RegExp((y + 7).toString() + " GMT"));

                    done();
                });

            });
        });
    });

});

describe("CertificateManager managing certificate", function() {

    this.timeout(400000);

    const test = beforeTest(this);
    let cm: pki.CertificateManager;

    function createSampleCertificateDer(
        certificate: Filename,
        callback: (err: Error | null) => void
    ) {
        processAltNames({applicationUri: "T"});
        const defaultOpensslConfPath = path.join(__dirname, "../tmp/PKI2/own/openssl.cnf");
        const defaultOpensslConf = generateStaticConfig(defaultOpensslConfPath);

        certificate = make_path(certificate);
        // openssl req -x509 -days 365 -nodes -newkey rsa:1024 \
        //         -keyout private_key.pem -outform der -out certificate.der"

        execute_openssl("req " +
            "-x509 -days 365 -nodes -newkey rsa:1024 " +
            "-batch -keyout private_key.pem " +
            "-outform der -out " + q(n(certificate)) +
            " -config " + q(n(defaultOpensslConf)), {}, (err: Error | null) => {

            callback(err);
        });
    }

    const sample_certificate1_der = path.join(__dirname, "fixtures/sample_certificate1.der");
    const sample_certificate2_der = path.join(__dirname, "fixtures/sample_certificate2.der");
    const sample_certificate3_der = path.join(__dirname, "fixtures/sample_certificate3.der");
    const sample_certificate4_der = path.join(__dirname, "fixtures/sample_certificate4.der");

    before((done: ErrorCallback) => {
        const options = {
            location: path.join(test.tmpFolder, "PKI2")
        };
        cm = new pki.CertificateManager(options);

        async.series([
            (callback: ErrorCallback) => {
                cm.initialize(callback);
            },
            (callback: ErrorCallback) => {
                createSampleCertificateDer(sample_certificate1_der, (err: Error | null) => callback(err!));
            },
            (callback: ErrorCallback) => {
                createSampleCertificateDer(sample_certificate2_der, (err: Error | null) => callback(err!));
            },
            (callback: ErrorCallback) => {
                createSampleCertificateDer(sample_certificate3_der, (err: Error | null) => callback(err!));
            },
            (callback: ErrorCallback) => {
                createSampleCertificateDer(sample_certificate4_der, (err: Error | null) => callback(err!));
            },
        ], done);
    });

    it("Q1 - CertificateManager#_getCertificateStatus should return 'unknown' if the certificate is first seen",
        (done: ErrorCallback) => {

            const certificate: Buffer = fs.readFileSync(sample_certificate1_der);
            certificate.should.be.instanceOf(Buffer);

            async.series([
            (callback: ErrorCallback) => {
                execute_openssl("x509 -inform der -in " + q(n(sample_certificate1_der)) + " " +
                    "-fingerprint -noout ", {}, (err: Error | null) => {
                    callback(err!);
                });
            },
            (callback: ErrorCallback) => {
                cm._getCertificateStatus(certificate, (err: Error | null, status?: CertificateStatus) => {
                    status!.should.eql("unknown");
                    callback();
                });
            }
        ], done);

    });

    it("Q2 - CertificateManager#getCertificateStatus should store unknown certificate into the untrusted folder",
        (done: ErrorCallback) => {

            const certificate: Buffer = fs.readFileSync(sample_certificate2_der);

            async.series([
            (callback: ErrorCallback) => {
                cm.getCertificateStatus(certificate, (err: Error | null, status?: CertificateStatus) => {
                    status!.should.eql("rejected");
                    callback();
                });
            },
            (callback: ErrorCallback) => {
                cm.getCertificateStatus(certificate, (err: Error | null, status?: CertificateStatus) => {
                    status!.should.eql("rejected");
                    callback();
                });
            }
        ], done);
    });

    it("Q3 - CertificateManager#trustCertificate  should store in trusted folder", (done: ErrorCallback) => {

        const certificate: Buffer = fs.readFileSync(sample_certificate3_der);

        async.series([
            (callback: ErrorCallback) => {
                cm.getCertificateStatus(certificate, (err: Error | null, status?: CertificateStatus) => {
                    status!.should.eql("rejected");
                    callback();
                });
            },
            (callback: ErrorCallback) => {
                cm.trustCertificate(certificate, (err?: Error | null) => {
                    should(err).eql(null);
                    callback();
                });
            },
            (callback: ErrorCallback) => {
                cm.getCertificateStatus(certificate, (err: Error | null, status?: CertificateStatus) => {
                    status!.should.eql("trusted");
                    callback();
                });
            },
            (callback: ErrorCallback) => {
                cm.rejectCertificate(certificate, (err?: Error | null) => {
                    should(err).eql(null);
                    callback();
                });
            },
            (callback: ErrorCallback) => {
                cm.getCertificateStatus(certificate, (err: Error | null, status?: CertificateStatus) => {
                    status!.should.eql("rejected");
                    callback();
                });
            },
            (callback: ErrorCallback) => {
                cm.rejectCertificate(certificate, (err?: Error | null) => {
                    // already rejectied
                    should(err).eql(undefined);
                    callback();
                });
            }
        ], done);

    });

    it("Q4 - Async CertificateManager#trustCertificate  should store in trusted folder", async () => {

        const fsReadFile = promisify(fs.readFile);

        const certificate: Buffer = await fsReadFile(sample_certificate3_der);

        const status = await cm.getCertificateStatus(certificate);

        status.should.eql("rejected");

        await cm.trustCertificate(certificate);

        const status1 = await cm.getCertificateStatus(certificate);
        status1.should.eql("trusted");

        const status1_a = await cm.isCertificateTrusted(certificate);
        status1_a.should.eql("Good");

        await cm.rejectCertificate(certificate);

        const status2 = await cm.getCertificateStatus(certificate);
        status2.should.eql("rejected");

        const status2_a = await cm.isCertificateTrusted(certificate);
        status2_a.should.eql("BadCertificateUntrusted");

        await cm.rejectCertificate(certificate);

    });
    it("Q5 - isCertificateTrusted with invalid certificate", async () => {

        const badCertificate = Buffer.from("bad certificate");
        const status2_a = await cm.isCertificateTrusted(badCertificate);
        status2_a.should.eql("BadCertificateInvalid");

    });
    it("Q6 - isCertificateTrusted", async () => {

        const fsReadFile = promisify(fs.readFile);

        const certificate: Buffer = await fsReadFile(sample_certificate3_der);
        const status = await cm.isCertificateTrusted(certificate);
        status.should.eql("BadCertificateUntrusted");

        await cm.trustCertificate(certificate);

        const status1 = await cm.isCertificateTrusted(certificate);
        status1.should.eql("Good");

        await cm.rejectCertificate(certificate);

        const status2 = await cm.isCertificateTrusted(certificate);
        status2.should.eql("BadCertificateUntrusted");

        await cm.rejectCertificate(certificate);

    });
});

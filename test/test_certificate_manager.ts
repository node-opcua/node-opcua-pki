Error.stackTraceLimit = Infinity;

// tslint:disable: no-console
// tslint:disable:variable-name
// tslint:disable:no-shadowed-variable
import fs from "node:fs";
import path from "node:path";
import "should";
import { readCertificate } from "node-opcua-crypto";
import { CertificateManager, type CertificateStatus, type Filename, g_config, makePath, quote } from "../lib";
import { dumpCertificate, executeOpensslAsync, generateStaticConfig, processAltNames } from "../lib/toolbox/with_openssl";
import { beforeTest, grep } from "./helpers";

const q = quote;
const n = makePath;

describe("CertificateManager", function (this: Mocha.Suite) {
    this.timeout(40000);

    const testData = beforeTest(this);

    it("should create a certificateManager", async () => {
        const options = {
            location: path.join(testData.tmpFolder, "PKI")
        };

        const cm = new CertificateManager(options);

        await cm.initialize();

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

        await cm.dispose();
    });

    it("should create its own self-signed certificate", async () => {
        function get_days(date1: Date, date2: Date): number {
            const ms_in_one_day = 24 * 3600000;
            const diff = date1.getTime() - date2.getTime();
            return Math.round(diff / ms_in_one_day);
        }

        const options = {
            location: path.join(testData.tmpFolder, "PKI1")
        };

        const cm = new CertificateManager(options);

        await cm.initialize();

        const now = new Date();
        const endDate = new Date(now.getFullYear() + 7, 10, 10);
        const duration = get_days(endDate, now);

        const params = {
            applicationUri: "MY:APPLICATION:URI",

            dns: ["some.other.domain.com", "my.domain.com"],
            ip: ["192.123.145.121"],
            subject: "CN=MyCommonName",
            // can only be TODAY due to openssl limitation : startDate: new Date(2010,2,2),
            validity: duration,

            startDate: now
        };

        await cm.createSelfSignedCertificate(params);

        const expectedCertificate = path.join(options.location, "own/certs/self_signed_certificate.pem");
        fs.existsSync(expectedCertificate).should.eql(true, "self-signed certificate must exist");

        const data = (await dumpCertificate(expectedCertificate)) as string;

        await fs.promises.writeFile(path.join(testData.tmpFolder, "dump_cert1.txt"), data as string);

        grep(data, /URI/).should.match(/URI:MY:APPLICATION:URI/);
        grep(data, /DNS/).should.match(/DNS:some.other.domain.com/);
        grep(data, /DNS/).should.match(/DNS:my.domain.com/);

        if (g_config.opensslVersion.match(/1.0.2/)) {
            // note openssl version 1.0.1 does support sha256 signature
            grep(data, /Signature Algorithm/).should.match(/Signature Algorithm: sha256WithRSAEncryption/);
        }
        grep(data, /Self-signed/).should.match(/Self-signed/);

        // the self-signed certificate should contain
        //     Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement
        grep(data, /Digital Signature/).should.match(/Digital Signature/);
        grep(data, /Key Encipherment/).should.match(/Key Encipherment/);
        grep(data, /Data Encipherment/).should.match(/Data Encipherment/);

        // the self-signed certificate should not contain CRL Sign
        grep(data, /CRL Sign/).should.eql("");

        const y = new Date().getFullYear();
        grep(data, /Not Before/).should.match(new RegExp(`${y.toString()} GMT`));
        grep(data, /Not After/).should.match(new RegExp(`${(y + 7).toString()} GMT`));

        await cm.dispose();
    });
});

describe("CertificateManager managing certificate", function (this: Mocha.Suite) {
    this.timeout(400000);

    const testData = beforeTest(this);
    let cm: CertificateManager;

    async function createSampleCertificateDer(certificate: Filename): Promise<void> {
        processAltNames({ applicationUri: "T" });
        const defaultOpensslConfPath = path.join(__dirname, "../tmp/PKI2/own/openssl.cnf");
        const defaultOpensslConf = generateStaticConfig(defaultOpensslConfPath);

        certificate = makePath(certificate);
        // openssl req -x509 -days 365 -nodes -newkey rsa:1024 \
        //         -keyout private_key.pem -outform der -out certificate.der"
        await executeOpensslAsync(
            "req " +
                "-x509 -days 365 -nodes -newkey rsa:1024 " +
                "-batch -keyout private_key.pem " +
                "-outform der -out " +
                q(n(certificate)) +
                " -config " +
                q(n(defaultOpensslConf)),
            {}
        );
    }

    const sample_certificate1_der = path.join(__dirname, "fixtures/sample_certificate1.der");
    const sample_certificate2_der = path.join(__dirname, "fixtures/sample_certificate2.der");
    const sample_certificate3_der = path.join(__dirname, "fixtures/sample_certificate3.der");
    const sample_certificate4_der = path.join(__dirname, "fixtures/sample_certificate4.der");

    before(async () => {
        const options = {
            location: path.join(testData.tmpFolder, "PKI2")
        };
        cm = new CertificateManager(options);

        await cm.initialize();
        await createSampleCertificateDer(sample_certificate1_der);
        await createSampleCertificateDer(sample_certificate2_der);
        await createSampleCertificateDer(sample_certificate3_der);
        await createSampleCertificateDer(sample_certificate4_der);

        await cm.dispose();
    });

    it("Q1 - CertificateManager#_getCertificateStatus should return 'unknown' if the certificate is first seen", async () => {
        const certificate: Buffer = fs.readFileSync(sample_certificate1_der);
        certificate.should.be.instanceOf(Buffer);
        await executeOpensslAsync(`x509 -inform der -in ${q(n(sample_certificate1_der))} -fingerprint -noout `, {});
        const status: CertificateStatus = await cm._checkRejectedOrTrusted(certificate);
        status.should.eql("unknown");
    });

    it("Q2 - CertificateManager#getCertificateStatus should store unknown certificate into the untrusted folder", async () => {
        const certificate: Buffer = fs.readFileSync(sample_certificate2_der);

        const status1: CertificateStatus = await cm.getCertificateStatus(certificate);
        status1.should.eql("rejected");

        const status2: CertificateStatus = await cm.getCertificateStatus(certificate);
        status2.should.eql("rejected");
    });

    it("Q3 - CertificateManager#trustCertificate should store in trusted folder", async () => {
        const certificate: Buffer = fs.readFileSync(sample_certificate3_der);

        const status1: CertificateStatus = await cm.getCertificateStatus(certificate);
        status1.should.eql("rejected");

        await cm.trustCertificate(certificate);
        const status2: CertificateStatus = await cm.getCertificateStatus(certificate);
        status2.should.eql("trusted");

        await cm.rejectCertificate(certificate);

        const status3: CertificateStatus = await cm.getCertificateStatus(certificate);
        status3.should.eql("rejected");

        await cm.rejectCertificate(certificate);
    });

    it("Q4 - Async CertificateManager#trustCertificate  should store in trusted folder", async () => {
        const fsReadFile = fs.promises.readFile;

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
        const fsReadFile = fs.promises.readFile;

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

    it("Q7 - Checking certificate", async () => {
        await cm.initialize();

        const sample_certificate3_pem = path.join(__dirname, "fixtures/sample_server_selfSigned1.pem");

        const certificate = await readCertificate(sample_certificate3_pem);
        await cm.trustCertificate(certificate);

        const status = await cm.getCertificateStatus(certificate);
        console.log("status ", status.toString());

        const verificationStatus = await cm.verifyCertificate(certificate);
        console.log("status ", verificationStatus.toString());
    });

    it("Q8A - Disposing while initializing ", async () => {
        const options = {
            location: path.join(testData.tmpFolder, "PKI_aa")
        };
        const cm = new CertificateManager(options);
        await cm.initialize();
        console.log("initialized done");
        cm.dispose();
    });
    it("Q8B - Disposing while initializing ", async () => {
        const options = {
            location: path.join(testData.tmpFolder, "PKI_aa")
        };
        const cm = new CertificateManager(options);

        const promises: Promise<void>[] = [
            (async () => {
                await cm.initialize();
                console.log("initialized done");
            })(),
            (async () => {
                await new Promise<void>((resolve) => {
                    setImmediate(() => {
                        cm.dispose();
                        console.log("disposed");
                        resolve();
                    });
                });
            })()
        ];
        await Promise.all(promises);
    });
});

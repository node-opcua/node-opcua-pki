// tslint:disable:no-console
// tslint:disable:no-shadowed-variable

import fs from "node:fs";
import path from "node:path";
import {
    type Certificate,
    certificateMatchesPrivateKey,
    exploreCertificate,
    exploreCertificateSigningRequest,
    readCertificate,
    readCertificateRevocationList,
    readPrivateKey,
    rsaLengthPrivateKey,
    split_der
} from "node-opcua-crypto";
import {
    CertificateAuthority,
    type CertificateAuthorityOptions,
    CertificateManager,
    type Filename,
    VerificationStatus
} from "node-opcua-pki";
import type { Params } from "node-opcua-pki-priv/toolbox/common";
import { g_config } from "node-opcua-pki-priv/toolbox/config";
import { execute_openssl, x509Date } from "node-opcua-pki-priv/toolbox/with_openssl";

import { beforeTest } from "./helpers";

const doDebug = !!process.env.DEBUG;

describe("Certificate Authority", function (this: Mocha.Suite) {
    const testData = beforeTest(this);
    let options: Partial<CertificateAuthorityOptions> = {};
    before(() => {
        options = {
            keySize: 2048,
            location: path.join(testData.tmpFolder, "CA")
        };
    });

    it("should read openssl version", async () => {
        let output = await execute_openssl("version", { cwd: "." });
        output = output?.trim();
        g_config.opensslVersion.should.eql(output);
    });

    it("should create a CertificateAuthority", async () => {
        const ca = new CertificateAuthority(options as CertificateAuthorityOptions);
        await ca.initialize();
    });
});

describe("Signing Certificate with Certificate Authority", function (this: Mocha.Suite) {
    const testData = beforeTest(this);

    let theCertificateAuthority: CertificateAuthority;
    let someCertificateManager: CertificateManager;

    before(async () => {
        theCertificateAuthority = new CertificateAuthority({
            keySize: 2048,
            location: path.join(testData.tmpFolder, "CA")
        });

        someCertificateManager = new CertificateManager({
            location: path.join(testData.tmpFolder, "PI")
        });

        await someCertificateManager.initialize();
        await theCertificateAuthority.initialize();

        await someCertificateManager.dispose();
    });

    async function createCertificateRequest(): Promise<string> {
        // let create a certificate request from the certificate manager
        const params = {
            applicationUri: "MY:APPLICATION:URI",
            dns: ["localhost", "my.domain.com"],
            ip: ["192.123.145.121"],
            subject: "/CN=MyCommonName",
            // can only be TODAY due to openssl limitation : startDate: new Date(2010,2,2),
            validity: 365 * 7
        };
        const certificateSigningRequestFilename = await someCertificateManager.createCertificateRequest(params);
        return certificateSigningRequestFilename;
    }
    async function verifyCertificateAgainstPrivateKey(certificate: Certificate) {
        console.log("someCertificateManager.privateKey=", someCertificateManager.privateKey);
        const privateKey = readPrivateKey(someCertificateManager.privateKey);
        const _rsaLength = rsaLengthPrivateKey(privateKey);

        if (!certificateMatchesPrivateKey(certificate, privateKey)) {
            throw new Error("Certificate and private key do not match !!!");
        }
    }

    it("T0 - should have a CA Certificate", async () => {
        fs.existsSync(theCertificateAuthority.caCertificate).should.eql(true);
    });

    it("T1 - should have a CA Certificate with a CRL", async () => {
        await theCertificateAuthority.constructCACertificateWithCRL();
        fs.existsSync(theCertificateAuthority.caCertificateWithCrl).should.eql(true);
    });

    it("T2 - should sign a Certificate Request", async () => {
        const self = {
            certificateRequest: ""
        };

        // create a Certificate Signing Request
        self.certificateRequest = await createCertificateRequest();

        fs.existsSync(self.certificateRequest).should.eql(true);

        const certificateFilename = path.join(testData.tmpFolder, "sample_certificate.pem");

        const params = {
            applicationUri: "BAD SHOULD BE IN REQUEST",
            startDate: new Date(2011, 25, 12),
            validity: 10 * 365
        };

        await theCertificateAuthority.signCertificateRequest(certificateFilename, self.certificateRequest, params);

        fs.existsSync(certificateFilename).should.eql(true, `certificate file ${certificateFilename} must exist`);

        // Serial Number: 4096 (0x1000)

        const certificateChain = readCertificate(certificateFilename);
        const elements = split_der(certificateChain);
        elements.length.should.eql(2);
        // should have 2 x -----BEGIN CERTIFICATE----- in the chain

        // should verify that certificate is valid
        // verify the subject Alternative Name
        const csr = readCertificate(self.certificateRequest);
        const infoCSR = exploreCertificateSigningRequest(csr);

        const info = exploreCertificate(certificateChain);

        if (doDebug) {
            console.log(infoCSR.extensionRequest.basicConstraints);
            console.log(info.tbsCertificate.extensions?.basicConstraints);

            console.log(infoCSR.extensionRequest.keyUsage);
            console.log(info.tbsCertificate.extensions?.keyUsage);

            console.log(infoCSR.extensionRequest.subjectAltName);
            console.log(info.tbsCertificate.extensions?.subjectAltName);
        }
        infoCSR.extensionRequest.subjectAltName.should.eql(info.tbsCertificate.extensions?.subjectAltName);

        // todo

        await verifyCertificateAgainstPrivateKey(elements[0]);
    });

    async function sign(certificateRequest: Filename, startDate: Date, validity: number): Promise<string> {
        const a = `${x509Date(startDate)}_${validity}`;

        fs.existsSync(certificateRequest).should.eql(true, `certificate request ${certificateRequest} must exist`);

        const certificateFilename = path.join(testData.tmpFolder, `sample_certificate${a}.pem`);

        const params = {
            applicationUri: "BAD SHOULD BE IN REQUEST",
            startDate,
            validity
        };
        if (fs.existsSync(certificateFilename)) {
            fs.unlinkSync(certificateFilename);
        }
        const certificate = await theCertificateAuthority.signCertificateRequest(certificateFilename, certificateRequest, params);

        fs.existsSync(certificate).should.eql(true, `certificate: ${certificateFilename} should exists`);
        // Serial Number: 4096 (0x1000)

        // should have 2 x -----BEGIN CERTIFICATE----- in the chain
        return certificate;
    }

    const now = new Date();
    const lastYear = new Date();
    lastYear.setFullYear(now.getFullYear() - 1);
    const nextYear = new Date();
    nextYear.setFullYear(now.getFullYear() + 1);

    it("T3 - should create various Certificates signed by the CA authority", async () => {
        // create a Certificate Signing Request
        const certificateRequest = await createCertificateRequest();
        fs.existsSync(certificateRequest).should.eql(true, `certificate request ${certificateRequest} must exist`);
        await sign(certificateRequest, lastYear, 200);
        await sign(certificateRequest, lastYear, 10 * 365); // valid
        await sign(certificateRequest, nextYear, 365); // not started yet
    });

    it("T4 - should create various self-signed Certificates using the CA", async () => {
        // using a CA to construct self-signed certificates provides the following benefits:
        //    - startDate can be easily specified in the past or the future
        //    - certificate can be revoked ??? to be checked.

        const privateKey = someCertificateManager.privateKey;
        const certificate = path.join(testData.tmpFolder, "sample_self_signed_certificate.pem");

        fs.existsSync(certificate).should.eql(false, `${certificate} must not exist`);

        await theCertificateAuthority.createSelfSignedCertificate(certificate, privateKey, {
            applicationUri: "SomeUri"
        });

        fs.existsSync(certificate).should.eql(true);

        await verifyCertificateAgainstPrivateKey(readCertificate(certificate));
    });

    /**
     *
     * @param certificate  {String} certificate to create
     */
    async function createSelfSignedCertificate(certificate: Filename, privateKey: Filename): Promise<string> {
        const startDate = new Date();
        const validity = 1000;
        const params: Params = {
            applicationUri: "BAD SHOULD BE IN REQUEST",
            startDate,
            validity
        };
        await theCertificateAuthority.createSelfSignedCertificate(certificate, privateKey, params);

        // console.log("signed_certificate = signed_certificate", certificate);
        return certificate;
    }

    it("T5 - should revoke a self-signed certificate", async () => {
        const privateKey = someCertificateManager.privateKey;
        const certificate = path.join(testData.tmpFolder, "certificate_to_be_revoked1.pem");

        await createSelfSignedCertificate(certificate, privateKey);
        fs.existsSync(certificate).should.eql(true);

        await theCertificateAuthority.revokeCertificate(certificate, {});
    });

    async function createCertificateFromCA(): Promise<string> {
        const certificateRequest = await createCertificateRequest();

        const signedCertificate = await sign(certificateRequest, lastYear, 10 * 365 + 10);

        return signedCertificate;
    }

    it("T6 - should revoke a certificate emitted by the CA", async () => {
        // g_config.silent = false;

        const caCertificateFilename = theCertificateAuthority.caCertificate;
        const caCRLFilename = theCertificateAuthority.revocationList;
        const caCertificate = await readCertificate(caCertificateFilename);
        const caCRLBefore = await readCertificateRevocationList(caCRLFilename);

        const certificateFilename = await createCertificateFromCA();
        fs.existsSync(certificateFilename).should.eql(true);
        const certificate = await readCertificate(certificateFilename);

        // ---- lets create a
        const pkiLocation = path.join(testData.tmpFolder, "somePKI");
        const cm = new CertificateManager({
            location: pkiLocation
        });
        await cm.initialize();

        const status1 = await cm.addIssuer(caCertificate, true, true);
        status1.should.eql(VerificationStatus.Good);
        const status4 = await cm.addRevocationList(caCRLBefore);
        status4.should.eql(VerificationStatus.Good);

        // check status before revocation...
        const validate1 = await cm.verifyCertificate(certificate);
        validate1.should.eql(VerificationStatus.Good);

        // now revoke certificate
        await theCertificateAuthority.revokeCertificate(certificateFilename, {});

        const caCRLAfter = await readCertificateRevocationList(caCRLFilename);

        const status3 = await cm.addRevocationList(caCRLAfter);
        status3.should.eql(VerificationStatus.Good);

        const validate2 = await cm.verifyCertificate(certificate);
        validate2.should.eql(VerificationStatus.BadCertificateRevoked);

        await cm.dispose();
    });

    it("T7 - it should automatically accept Certificate issued by a trusted issuer that is not in the CRL", async () => {
        const caCertificateFilename = theCertificateAuthority.caCertificate;
        const caCRLFilename = theCertificateAuthority.revocationList;
        const caCertificate = await readCertificate(caCertificateFilename);
        const caCRLBefore = await readCertificateRevocationList(caCRLFilename);

        const certificateFilename = await createCertificateFromCA();
        fs.existsSync(certificateFilename).should.eql(true);
        const certificate = await readCertificate(certificateFilename);

        // ---- lets create a
        const pkiLocation = path.join(testData.tmpFolder, "somePKI1");
        const cm = new CertificateManager({
            location: pkiLocation
        });
        await cm.initialize();

        const validate0 = await cm.verifyCertificate(certificate);
        validate0.should.eql(VerificationStatus.BadCertificateChainIncomplete);

        const _status1 = await cm.addIssuer(caCertificate);
        const _status2 = await cm.addRevocationList(caCRLBefore);

        const validate1 = await cm.verifyCertificate(certificate);
        validate1.should.eql(VerificationStatus.BadCertificateUntrusted);

        await cm.dispose();
    });
});

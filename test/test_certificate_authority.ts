// tslint:disable:no-console
// tslint:disable:no-shadowed-variable

import * as fs from "fs";
import * as path from "path";
import { 
    readCertificate, 
    split_der, 
    readCertificateRevocationList, 
    exploreCertificate,
    exploreCertificateSigningRequest
} from "node-opcua-crypto";
import {  } from "node-opcua-crypto";

import should = require("should");

import {
    ErrorCallback,
    execute_openssl,
    Filename,
    g_config,
    Params,
    x509Date,
    CertificateAuthority,
    CertificateManager,
    VerificationStatus,
} from "..";

import { beforeTest } from "./helpers";

const _should = should;
const doDebug = !!process.env.DEBUG;

describe("Certificate Authority", function (this: Mocha.Suite) {
    const testData = beforeTest(this);
    let options: any = {};
    before(() => {
        options = {
            keySize: 2048,
            location: path.join(testData.tmpFolder, "CA"),
        };
    });

    it("should read openssl version", (done: ErrorCallback) => {
        execute_openssl("version", { cwd: "." }, (err: Error | null, output?: string) => {
            if (err) {
                return done(err);
            }
            output = output!.trim();
            g_config.opensslVersion.should.eql(output);
            done(err!);
        });
    });

    it("should create a CertificateAuthority", async () => {
        const ca = new CertificateAuthority(options);
        await ca.initialize();
    });
});

describe("Signing Certificate with Certificate Authority", function (this: Mocha.Suite) {
    const testData = beforeTest(this);

    let ca: CertificateAuthority;
    let cm: CertificateManager;

    before(async () => {
        ca = new CertificateAuthority({
            keySize: 2048,
            location: path.join(testData.tmpFolder, "CA"),
        });

        cm = new CertificateManager({
            location: path.join(testData.tmpFolder, "PI"),
        });

        await cm.initialize();
        await ca.initialize();
    });

    async function createCertificateRequest(): Promise<string> {
        // let create a certificate request from the certificate manager
        const params = {
            applicationUri: "MY:APPLICATION:URI",
            dns: ["localhost", "my.domain.com"],
            ip: ["192.123.145.121"],
            subject: "/CN=MyCommonName",
            // can only be TODAY due to openssl limitation : startDate: new Date(2010,2,2),
            validity: 365 * 7,
        };
        const certificateSigningRequestFilename = await cm.createCertificateRequest(params);
        return certificateSigningRequestFilename;
    }

    it("T0 - should have a CA Certificate", async () => {
        fs.existsSync(ca.caCertificate).should.eql(true);
    });

    it("T1 - should have a CA Certificate with a CRL", async () => {
        await ca.constructCACertificateWithCRL();
        fs.existsSync(ca.caCertificateWithCrl).should.eql(true);
    });

    it("T2 - should sign a Certificate Request", async () => {

        const self = {
            certificateRequest: "",
        };

        // create a Certificate Signing Request
        self.certificateRequest = await createCertificateRequest();

        fs.existsSync(self.certificateRequest).should.eql(true);

        const certificateFilename = path.join(testData.tmpFolder, "sample_certificate.pem");

        const params = {
            applicationUri: "BAD SHOULD BE IN REQUEST",
            startDate: new Date(2011, 25, 12),
            validity: 10 * 365,
        };

        await ca.signCertificateRequest(certificateFilename, self.certificateRequest, params);

        fs.existsSync(certificateFilename!).should.eql(true, "certificate file " + certificateFilename + " must exist");

        // Serial Number: 4096 (0x1000)

        const certificateChain = readCertificate(certificateFilename);
        const elements = split_der(certificateChain);
        elements.length.should.eql(2);
        // should have 2 x -----BEGIN CERTIFICATE----- in the chain

        // should verify that certificate is valid
        // verify the subject Alternatibve Name 
        const csr = readCertificate( self.certificateRequest);
        const infoCSR = exploreCertificateSigningRequest(csr);
        
        const info = exploreCertificate(certificateChain);

        if (doDebug) {
            console.log(infoCSR.extensionRequest.basicConstraints);
            console.log(info.tbsCertificate.extensions.basicConstraints);
    
            console.log(infoCSR.extensionRequest.keyUsage);
            console.log(info.tbsCertificate.extensions.keyUsage);
    
            console.log(infoCSR.extensionRequest.subjectAltName);
            console.log(info.tbsCertificate.extensions.subjectAltName);    
        }
        infoCSR.extensionRequest.subjectAltName.should.eql(info.tbsCertificate.extensions.subjectAltName);

        // todo
    });

    async function sign(certificateRequest: Filename, startDate: Date, validity: number): Promise<string> {
        const a = x509Date(startDate) + "_" + validity;

        fs.existsSync(certificateRequest).should.eql(true, "certificate request " + certificateRequest + " must exist");

        const certificateFilename = path.join(testData.tmpFolder, "sample_certificate" + a + ".pem");

        const params = {
            applicationUri: "BAD SHOULD BE IN REQUEST",
            startDate,
            validity,
        };
        if (fs.existsSync(certificateFilename!)) {
            fs.unlinkSync(certificateFilename!);
        }
        const certificate = await ca.signCertificateRequest(certificateFilename, certificateRequest, params);

        fs.existsSync(certificate!).should.eql(true, "certificate: " + certificateFilename + " should exists");
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
        fs.existsSync(certificateRequest).should.eql(true, "certificate request " + certificateRequest + " must exist");
        await sign(certificateRequest, lastYear, 200);
        await sign(certificateRequest, lastYear, 10 * 365); // valid
        await sign(certificateRequest, nextYear, 365); // not started yet
    });

    it("T4 - should create various self-signed Certificates using the CA", async () => {
        // using a CA to construct self-signed certificates provides the following benefits:
        //    - startDate can be easily specified in the past or the future
        //    - certificate can be revoked ??? to be checked.

        const privateKey = cm.privateKey;
        const certificate = path.join(testData.tmpFolder, "sample_self_signed_certificate.pem");

        fs.existsSync(certificate).should.eql(false, certificate + " must not exist");

        await ca.createSelfSignedCertificate(certificate, privateKey, {
            applicationUri: "SomeUri",
        });

        fs.existsSync(certificate).should.eql(true);
    });

    /**
     *
     * @param certificate  {String} certificate to create
     * @param privateKey
     * @param callback
     */
    async function createSelfSignedCertificate(certificate: Filename, privateKey: Filename): Promise<string> {
        const startDate = new Date();
        const validity = 1000;
        const params: Params = {
            applicationUri: "BAD SHOULD BE IN REQUEST",
            startDate,
            validity,
        };
        await ca.createSelfSignedCertificate(certificate, privateKey, params);

        // console.log("signed_certificate = signed_certificate", certificate);
        return certificate;
    }

    it("T5 - should revoke a self-signed certificate", async () => {
        const privateKey = cm.privateKey;
        const certificate = path.join(testData.tmpFolder, "certificate_to_be_revoked1.pem");

        await createSelfSignedCertificate(certificate, privateKey);
        fs.existsSync(certificate).should.eql(true);

        await ca.revokeCertificate(certificate, {});
    });

    async function createCertificateFromCA(): Promise<string> {
        const certificateRequest = await createCertificateRequest();

        const signedCertificate = await sign(certificateRequest, lastYear, 10 * 365 + 10);

        return signedCertificate;
    }

    it("T6 - should revoke a certificate emitted by the CA", async () => {
        // g_config.silent = false;

        const caCertificateFilename = ca.caCertificate;
        const caCRLFilename = ca.revocationList;
        const caCertificate = await readCertificate(caCertificateFilename);
        const caCRLBefore = await readCertificateRevocationList(caCRLFilename);

        const certificateFilename = await createCertificateFromCA();
        fs.existsSync(certificateFilename).should.eql(true);
        const certificate = await readCertificate(certificateFilename);

        // ---- lets create a
        const pkiLocation = path.join(testData.tmpFolder, "somePKI");
        const cm = new CertificateManager({
            location: pkiLocation,
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
        await ca.revokeCertificate(certificateFilename, {});

        const caCRLAfter = await readCertificateRevocationList(caCRLFilename);

        const status3 = await cm.addRevocationList(caCRLAfter);
        status3.should.eql(VerificationStatus.Good);

        const validate2 = await cm.verifyCertificate(certificate);
        validate2.should.eql(VerificationStatus.BadCertificateRevoked);
    });

    it("T7 - it should automatically accept Certificate issued by a trusted issuer that is not in the CRL", async () => {
        const caCertificateFilename = ca.caCertificate;
        const caCRLFilename = ca.revocationList;
        const caCertificate = await readCertificate(caCertificateFilename);
        const caCRLBefore = await readCertificateRevocationList(caCRLFilename);

        const certificateFilename = await createCertificateFromCA();
        fs.existsSync(certificateFilename).should.eql(true);
        const certificate = await readCertificate(certificateFilename);

        // ---- lets create a
        const pkiLocation = path.join(testData.tmpFolder, "somePKI1");
        const cm = new CertificateManager({
            location: pkiLocation,
        });
        await cm.initialize();

        const validate0 = await cm.verifyCertificate(certificate);
        validate0.should.eql(VerificationStatus.BadSecurityChecksFailed);

        const status1 = await cm.addIssuer(caCertificate);
        const status2 = await cm.addRevocationList(caCRLBefore);

        const validate1 = await cm.verifyCertificate(certificate);
        validate1.should.eql(VerificationStatus.BadCertificateUntrusted);
    });
});

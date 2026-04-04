// tslint:disable:no-console
// tslint:disable:no-shadowed-variable

import fs from "node:fs";
import path from "node:path";
import {
    type Certificate,
    certificateMatchesPrivateKey,
    exploreCertificate,
    exploreCertificateSigningRequest,
    makeSHA1Thumbprint,
    readCertificateChain,
    readCertificateChainAsync,
    readCertificateRevocationList,
    readCertificateSigningRequest,
    readPrivateKey,
    rsaLengthPrivateKey,
    split_der,
    toPem
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
import should from "should";

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

    it("should recover from partial CA init (key exists, cert missing)", async () => {
        // Simulate a partial init: create directory with cakey.pem but no cacert.pem
        const partialCALocation = path.join(testData.tmpFolder, "CA_partial");
        const privateDir = path.join(partialCALocation, "private");
        const publicDir = path.join(partialCALocation, "public");

        fs.mkdirSync(privateDir, { recursive: true });
        fs.mkdirSync(publicDir, { recursive: true });

        // Create a dummy private key file to simulate the partial state
        fs.writeFileSync(path.join(privateDir, "cakey.pem"), "STALE KEY DATA");

        // cacert.pem intentionally NOT created

        const ca = new CertificateAuthority({
            keySize: 2048,
            location: partialCALocation
        });

        // initialize() should detect the partial state, clean up, and rebuild
        await ca.initialize();

        // After recovery, both files should exist
        fs.existsSync(path.join(privateDir, "cakey.pem")).should.eql(true);
        fs.existsSync(path.join(publicDir, "cacert.pem")).should.eql(true);

        // The CA should be functional — verify we can get the cert
        const der = ca.getCACertificateDER();
        Buffer.isBuffer(der).should.eql(true);
        der.length.should.be.greaterThan(0);
        der[0].should.eql(0x30); // DER SEQUENCE
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
        doDebug && console.log("someCertificateManager.privateKey=", someCertificateManager.privateKey);
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

    // ------- Buffer-based accessors (US-059) -------

    it("T1a - getCACertificateDER() should return a DER buffer", () => {
        const der = theCertificateAuthority.getCACertificateDER();
        Buffer.isBuffer(der).should.eql(true);
        der.length.should.be.greaterThan(0);
        // DER-encoded certificates start with 0x30 (SEQUENCE)
        der[0].should.eql(0x30);
    });

    it("T1b - getCACertificatePEM() should return a PEM string", () => {
        const pem = theCertificateAuthority.getCACertificatePEM();
        pem.should.be.a.String();
        pem.should.startWith("-----BEGIN CERTIFICATE-----");
        pem.should.match(/-----END CERTIFICATE-----/);
    });

    it("T1c - getCRLDER() should return a DER buffer", () => {
        const der = theCertificateAuthority.getCRLDER();
        Buffer.isBuffer(der).should.eql(true);
        der.length.should.be.greaterThan(0);
        // DER-encoded CRLs also start with 0x30 (SEQUENCE)
        der[0].should.eql(0x30);
    });

    it("T1d - getCRLPEM() should return a PEM string", () => {
        const pem = theCertificateAuthority.getCRLPEM();
        pem.should.be.a.String();
        pem.length.should.be.greaterThan(0);
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

        const certificateChain = readCertificateChain(certificateFilename);
        certificateChain.length.should.eql(2);
        // should have 2 x -----BEGIN CERTIFICATE----- in the chain

        // should verify that certificate is valid
        // verify the subject Alternative Name
        const csr = await readCertificateSigningRequest(self.certificateRequest);
        const infoCSR = exploreCertificateSigningRequest(csr);

        const info = exploreCertificate(certificateChain[0]);

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

        await verifyCertificateAgainstPrivateKey(certificateChain[0]);
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
        const certificatePemFile = path.join(testData.tmpFolder, "sample_self_signed_certificate.pem");

        fs.existsSync(certificatePemFile).should.eql(false, `${certificatePemFile} must not exist`);

        await theCertificateAuthority.createSelfSignedCertificate(certificatePemFile, privateKey, {
            applicationUri: "SomeUri"
        });

        fs.existsSync(certificatePemFile).should.eql(true);

        await verifyCertificateAgainstPrivateKey(readCertificateChain(certificatePemFile)[0]);
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

    // ------- Buffer-based sign & revoke (US-058) -------

    it("T5a - signCertificateRequestFromDER() should sign a DER CSR and return DER cert", async () => {
        const csrFilename = await createCertificateRequest();
        // Read the CSR file produced by CertificateManager
        const csrDer = await readCertificateSigningRequest(csrFilename);

        const certDer = await theCertificateAuthority.signCertificateRequestFromDER(csrDer, {
            validity: 365
        });

        Buffer.isBuffer(certDer).should.eql(true);
        certDer.length.should.be.greaterThan(0);
        // DER-encoded certificates start with 0x30 (SEQUENCE)
        certDer[0].should.eql(0x30);

        // Should be parseable
        const info = exploreCertificate(certDer);
        const cn = info.tbsCertificate.subject.commonName;
        should.exist(cn);
        (cn as string).should.eql("MyCommonName");
    });

    it("T5a2 - signCertificateRequestFromDER() returns combined chain — callers must split before toPem", async () => {
        // This test reproduces the exact bug that caused BadCertificateInvalid
        // in GDS self-onboard: signCertificateRequestFromDER() returns
        // combine_der([leaf, CA, ...]), not just the leaf. When the caller
        // naively does toPem(combinedDER, "CERTIFICATE"), it creates a SINGLE
        // PEM block wrapping the concatenated DER bytes. readCertificateChain()
        // then sees one PEM block → returns [combinedDER] as element [0].
        //
        // The thumbprint of combinedDER ≠ thumbprint of leafDER, which causes
        // the server secure channel to reject the client's thumbprint.

        const csrFilename = await createCertificateRequest();
        const csrDer = await readCertificateSigningRequest(csrFilename);

        const signedCertDer = await theCertificateAuthority.signCertificateRequestFromDER(csrDer, {
            validity: 365
        });

        // 1. signCertificateRequestFromDER returns a COMBINED DER (leaf + CA chain)
        const certs = split_der(signedCertDer);
        certs.length.should.be.greaterThanOrEqual(2, "signCertificateRequestFromDER should return combined chain (leaf + CA)");

        const leafDer = certs[0];
        const leafThumbprint = makeSHA1Thumbprint(leafDer).toString("hex");
        const combinedThumbprint = makeSHA1Thumbprint(signedCertDer).toString("hex");

        // 2. PROVE THE BUG: thumbprints differ when computed on leaf vs combined
        leafThumbprint.should.not.eql(combinedThumbprint, "leaf thumbprint must differ from combined-chain thumbprint");

        // 3. DEMONSTRATE THE BUG: naive toPem(combinedDER) creates a SINGLE PEM block
        //    wrapping the concatenated bytes — readCertificateChain sees only 1 cert
        const buggyFile = path.join(testData.tmpFolder, "buggy_chain.pem");
        // BUG: toPem wraps the ENTIRE combined DER as one PEM block
        let buggyPem = toPem(signedCertDer, "CERTIFICATE");
        // ... then the caller might add CA chain AGAIN
        const caCertDer = theCertificateAuthority.getCACertificateDER();
        buggyPem += toPem(caCertDer, "CERTIFICATE");
        fs.writeFileSync(buggyFile, buggyPem, "ascii");

        // readCertificateChain sees 2 PEM blocks, but the first contains
        // the combined leaf+CA DER, and the second is the CA cert again
        const buggyChain = readCertificateChain(buggyFile);
        // The first element is the combined DER, NOT the leaf cert!
        const buggyThumbprint = makeSHA1Thumbprint(buggyChain[0]).toString("hex");
        buggyThumbprint.should.eql(combinedThumbprint, "buggy chain[0] thumbprint == combined thumbprint (NOT leaf!)");
        buggyThumbprint.should.not.eql(leafThumbprint, "buggy chain[0] thumbprint != leaf thumbprint — this is the mismatch!");

        // 4. DEMONSTRATE THE FIX: split_der first, then toPem each part
        const fixedFile = path.join(testData.tmpFolder, "fixed_chain.pem");
        let fixedPem = "";
        for (const cert of certs) {
            fixedPem += toPem(cert, "CERTIFICATE");
        }
        fs.writeFileSync(fixedFile, fixedPem, "ascii");

        const fixedChain = readCertificateChain(fixedFile);
        fixedChain.length.should.eql(certs.length, "fixed chain should have same number of certs as split_der");
        const fixedThumbprint = makeSHA1Thumbprint(fixedChain[0]).toString("hex");
        fixedThumbprint.should.eql(leafThumbprint, "fixed chain[0] thumbprint must equal leaf thumbprint");
    });

    it("T5b - revokeCertificateDER() should revoke a DER certificate", async () => {
        // Sign a cert first
        const csrFilename = await createCertificateRequest();
        const csrDer = await readCertificateSigningRequest(csrFilename);
        const certDer = await theCertificateAuthority.signCertificateRequestFromDER(csrDer, {
            validity: 365
        });

        // Get CRL before revocation
        const crlBefore = theCertificateAuthority.getCRLDER();

        // Revoke via DER
        await theCertificateAuthority.revokeCertificateDER(certDer, "keyCompromise");

        // CRL should have changed
        const crlAfter = theCertificateAuthority.getCRLDER();
        crlAfter.length.should.be.greaterThan(0);
        crlBefore.equals(crlAfter).should.eql(false);

        // Certificate should be marked as revoked in index.txt
        const info = exploreCertificate(certDer);
        const serial = info.tbsCertificate.serialNumber.replace(/:/g, "").toUpperCase();
        const revokeStatus = theCertificateAuthority.getCertificateStatus(serial);
        should.exist(revokeStatus);
        (revokeStatus as string).should.eql("revoked");
    });

    // ------- Certificate database API (US-057) -------

    it("T5c - getIssuedCertificates() should return records after signing", async () => {
        // At this point, several certs have been signed by earlier tests
        const records = theCertificateAuthority.getIssuedCertificates();
        records.length.should.be.greaterThan(0);

        const r = records[0];
        r.serial.should.be.a.String();
        r.status.should.be.oneOf(["valid", "revoked", "expired"]);
        r.subject.should.be.a.String();
        r.expiryDate.should.be.a.String();
    });

    it("T5d - getIssuedCertificateCount() should match records length", () => {
        const count = theCertificateAuthority.getIssuedCertificateCount();
        const records = theCertificateAuthority.getIssuedCertificates();
        count.should.eql(records.length);
    });

    it("T5e - getCertificateStatus() should return status for known serial", () => {
        const records = theCertificateAuthority.getIssuedCertificates();
        records.length.should.be.greaterThan(0);

        const serial = records[0].serial;
        const status = theCertificateAuthority.getCertificateStatus(serial);
        should.exist(status);
        (status as string).should.be.oneOf(["valid", "revoked", "expired"]);
    });

    it("T5f - getCertificateStatus() should return undefined for unknown serial", () => {
        const status = theCertificateAuthority.getCertificateStatus("DEADBEEF");
        (status === undefined).should.eql(true);
    });

    it("T5g - getCertificateBySerial() should return DER for known serial", () => {
        const records = theCertificateAuthority.getIssuedCertificates();
        records.length.should.be.greaterThan(0);

        const serial = records[0].serial;
        const der = theCertificateAuthority.getCertificateBySerial(serial);
        should.exist(der);
        Buffer.isBuffer(der as Buffer).should.eql(true);
        (der as Buffer)[0].should.eql(0x30); // DER SEQUENCE
    });

    it("T5h - getCertificateStatus() should return 'revoked' after revokeCertificateDER", async () => {
        // Sign a fresh cert
        const countBefore = theCertificateAuthority.getIssuedCertificateCount();

        const csrFilename = await createCertificateRequest();
        const csrDer = await readCertificateSigningRequest(csrFilename);
        const certDer = await theCertificateAuthority.signCertificateRequestFromDER(csrDer, {
            validity: 365
        });

        // Find the newly signed cert's serial via index.txt
        const recordsBefore = theCertificateAuthority.getIssuedCertificates();
        recordsBefore.length.should.be.greaterThan(countBefore);
        const serial = recordsBefore[recordsBefore.length - 1].serial;

        // Should be valid before revocation
        const statusBefore = theCertificateAuthority.getCertificateStatus(serial);
        should.exist(statusBefore);
        (statusBefore as string).should.eql("valid");

        // Revoke using the DER method (the bug fix!)
        await theCertificateAuthority.revokeCertificateDER(certDer, "keyCompromise");

        // Should be revoked after
        const statusAfter = theCertificateAuthority.getCertificateStatus(serial);
        should.exist(statusAfter);
        (statusAfter as string).should.eql("revoked");

        // Revoked record should have a revocationDate
        const revokedRecord = theCertificateAuthority.getIssuedCertificates().find((r) => r.serial === serial);
        should.exist(revokedRecord);
        should.exist((revokedRecord as { revocationDate?: string }).revocationDate);
    });

    // ------- generateKeyPairAndSignDER (US-113) -------

    it("T5i - generateKeyPairAndSignDER() should return cert + key DER buffers", async () => {
        const result = await theCertificateAuthority.generateKeyPairAndSignDER({
            applicationUri: "urn:test:US113:BasicTest",
            subject: "/CN=US113-Test",
            dns: ["localhost"],
            ip: ["127.0.0.1"],
            validity: 365
        });

        // Certificate should be a DER buffer
        Buffer.isBuffer(result.certificateDer).should.eql(true);
        result.certificateDer.length.should.be.greaterThan(0);
        result.certificateDer[0].should.eql(0x30); // DER SEQUENCE

        // Private key should exist
        should.exist(result.privateKey);

        // Certificate should be parseable
        const info = exploreCertificate(result.certificateDer);
        const cn = info.tbsCertificate.subject.commonName;
        should.exist(cn);
        (cn as string).should.eql("US113-Test");

        // Certificate and private key should match
        const matches = certificateMatchesPrivateKey(result.certificateDer, result.privateKey);
        matches.should.eql(true, "certificate and generated private key must match");

        // Private key should NOT be stored on disk by the CA
        const caDir = theCertificateAuthority.rootDir;
        const allFiles = fs.readdirSync(caDir, { recursive: true }) as string[];
        const privateKeyFiles = allFiles.filter((f) => f.includes("pki-keygen-"));
        privateKeyFiles.length.should.eql(0, "No temp key files should remain in CA directory");
    });

    it("T5j - generateKeyPairAndSignDER() should support custom keySize", async () => {
        const result = await theCertificateAuthority.generateKeyPairAndSignDER({
            applicationUri: "urn:test:US113:KeySize3072",
            subject: "/CN=US113-3072",
            keySize: 3072,
            validity: 180
        });

        Buffer.isBuffer(result.certificateDer).should.eql(true);
        should.exist(result.privateKey);

        // Verify the key size via the private key (rsaLengthPrivateKey returns bytes)
        const keyLength = rsaLengthPrivateKey(result.privateKey);
        keyLength.should.eql(3072 / 8);

        // Verify cert-key match
        certificateMatchesPrivateKey(result.certificateDer, result.privateKey).should.eql(true);
    });

    it("T5k - signCertificateRequestFromDER() should accept CA overrides", async () => {
        const csrFilename = await createCertificateRequest();
        const csrDer = await readCertificateSigningRequest(csrFilename);

        // Sign with custom DNS override
        const certDer = await theCertificateAuthority.signCertificateRequestFromDER(csrDer, {
            validity: 180,
            dns: ["override.example.com", "localhost"]
        });

        Buffer.isBuffer(certDer).should.eql(true);
        certDer[0].should.eql(0x30);

        const info = exploreCertificate(certDer);
        should.exist(info.tbsCertificate.extensions?.subjectAltName);
    });

    // ------- generateKeyPairAndSignPFX (PFX variant) -------

    it("T5l - generateKeyPairAndSignPFX() should return a PFX buffer", async () => {
        const pfx = await theCertificateAuthority.generateKeyPairAndSignPFX({
            applicationUri: "urn:test:US113:PfxBasic",
            subject: "/CN=US113-PFX-Test",
            dns: ["localhost"],
            validity: 365
        });

        Buffer.isBuffer(pfx).should.eql(true);
        pfx.length.should.be.greaterThan(0);
    });

    it("T5m - generateKeyPairAndSignPFX() should support passphrase", async () => {
        const passphrase = "test-password-123";
        const pfx = await theCertificateAuthority.generateKeyPairAndSignPFX({
            applicationUri: "urn:test:US113:PfxPassword",
            subject: "/CN=US113-PFX-Password",
            dns: ["localhost"],
            validity: 365,
            passphrase
        });

        Buffer.isBuffer(pfx).should.eql(true);
        pfx.length.should.be.greaterThan(0);

        // Verify we can extract info from the PFX with the correct password
        // Write to temp file, extract, verify
        const tmpPfx = path.join(testData.tmpFolder, "test_password.pfx");
        fs.writeFileSync(tmpPfx, pfx);

        const { extractCertificateFromPFX } = require("node-opcua-pki");
        const certPem = await extractCertificateFromPFX({
            pfxFile: tmpPfx,
            passphrase
        });
        certPem.should.containEql("BEGIN CERTIFICATE");
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

        const caCertificateChain = await readCertificateChainAsync(caCertificateFilename);
        const caCRLBefore = await readCertificateRevocationList(caCRLFilename);

        const certificateFilename = await createCertificateFromCA();
        fs.existsSync(certificateFilename).should.eql(true);
        const certificate = await readCertificateChainAsync(certificateFilename);

        // ---- lets create a
        const pkiLocation = path.join(testData.tmpFolder, "somePKI");
        const cm = new CertificateManager({
            location: pkiLocation
        });
        await cm.initialize();

        const status1 = await cm.addIssuers(caCertificateChain, true, true);
        status1.should.eql(VerificationStatus.Good);
        const status4 = await cm.addRevocationList(caCRLBefore);
        status4.should.eql(VerificationStatus.Good);

        // check status before revocation...
        const validate1 = await cm.verifyCertificate(certificate, { acceptCertificateWithValidIssuerChain: true });
        validate1.should.eql(VerificationStatus.Good);

        // now revoke certificate
        await theCertificateAuthority.revokeCertificate(certificateFilename, {});

        const caCRLAfter = await readCertificateRevocationList(caCRLFilename);

        const status3 = await cm.addRevocationList(caCRLAfter);
        status3.should.eql(VerificationStatus.Good);

        const validate2 = await cm.verifyCertificate(certificate, { acceptCertificateWithValidIssuerChain: true });
        validate2.should.eql(VerificationStatus.BadCertificateRevoked);

        await cm.dispose();
    });

    it("T7 - it should automatically accept Certificate issued by a trusted issuer that is not in the CRL", async () => {
        const caCertificateFilename = theCertificateAuthority.caCertificate;
        const caCRLFilename = theCertificateAuthority.revocationList;
        const caCertificateChain = await readCertificateChainAsync(caCertificateFilename);
        const caCRLBefore = await readCertificateRevocationList(caCRLFilename);

        const certificateFilename = await createCertificateFromCA();
        fs.existsSync(certificateFilename).should.eql(true);
        const certificateChain = await readCertificateChainAsync(certificateFilename);
        certificateChain.length.should.eql(2);

        // ---- lets create a
        const pkiLocation = path.join(testData.tmpFolder, "somePKI1");
        const cm = new CertificateManager({
            location: pkiLocation
        });
        await cm.initialize();

        // the certificateChain alone without its issuer
        // should be rejected because the chain is incomplete
        const validate0 = await cm.verifyCertificate([certificateChain[0]]);
        validate0.should.eql(VerificationStatus.BadCertificateChainIncomplete);

        // the certificateChain  should be rejected because
        // the issuer is not trusted, and the revocation list is not known
        const validate0b = await cm.verifyCertificate(certificateChain);
        validate0b.should.eql(VerificationStatus.BadCertificateRevocationUnknown);

        // the certificateChain  should be rejected because
        // although the chain is valid, the revocation list is not known
        const validate0c = await cm.verifyCertificate(certificateChain, {
            acceptCertificateWithValidIssuerChain: true,
            acceptCertificateWithUntrustedIssuer: true
        });
        validate0c.should.eql(VerificationStatus.BadCertificateRevocationUnknown);

        // // the certificateChain  should be rejected because
        // // although the chain is valid, the revocation list is not known, but that's ok
        // const validate0d = await cm.verifyCertificate(certificateChain, {
        //     acceptCertificateWithValidIssuerChain: true,
        //     acceptCertificateWithUntrustedIssuer: true,
        //     acceptCertificateWithoutCRL: true
        // });
        // validate0d.should.eql(VerificationStatus.Good);

        // the certificateChain  should be rejected because
        // although the chain is valid, the issuer is trusted,
        // but the revocation list is not known
        const _status1 = await cm.addIssuers(caCertificateChain, true, true);
        const validate1b = await cm.verifyCertificate(certificateChain);
        validate1b.should.eql(VerificationStatus.BadCertificateRevocationUnknown);

        const _status2 = await cm.addRevocationList(caCRLBefore);

        const validate1 = await cm.verifyCertificate(certificateChain);
        validate1.should.eql(VerificationStatus.BadCertificateUntrusted);

        await cm.dispose();
    });
});

describe("Intermediate CA Hierarchy", function (this: Mocha.Suite) {
    const testData = beforeTest(this);

    let rootCA: CertificateAuthority;
    let intermediateCA1: CertificateAuthority;
    let intermediateCA2: CertificateAuthority;

    before(async () => {
        // 1. Root CA (self-signed) — the only one that self-signs
        rootCA = new CertificateAuthority({
            keySize: 2048,
            location: path.join(testData.tmpFolder, "RootCA"),
            subject: "/CN=Test Root CA/O=TestOrg"
        });
        await rootCA.initialize();

        // 2. Intermediate CA #1 — manual 3-step workflow
        //    (simulates an external root CA that we don't own)
        intermediateCA1 = new CertificateAuthority({
            keySize: 2048,
            location: path.join(testData.tmpFolder, "IntermediateCA1"),
            subject: "/CN=Intermediate CA 1/O=TestOrg"
        });
        //   Step A: generate key + CSR (no signing yet)
        const result1 = await intermediateCA1.initializeCSR();
        result1.status.should.eql("created");
        //   Step B: Root CA signs the CSR with v3_ca extensions
        //          (output already contains [signedCert, rootCACert])
        const signedCert1 = path.join(testData.tmpFolder, "int1_signed.pem");
        await rootCA.signCACertificateRequest(signedCert1, (result1 as { csrPath: string }).csrPath, { validity: 3650 });
        //   Step C: install the chain (auto-splits into cacert.pem + issuer_chain.pem)
        await intermediateCA1.installCACertificate(signedCert1);

        // 3. Intermediate CA #2 — same manual workflow
        intermediateCA2 = new CertificateAuthority({
            keySize: 2048,
            location: path.join(testData.tmpFolder, "IntermediateCA2"),
            subject: "/CN=Intermediate CA 2/O=TestOrg"
        });
        const result2 = await intermediateCA2.initializeCSR();
        result2.status.should.eql("created");
        const signedCert2 = path.join(testData.tmpFolder, "int2_signed.pem");
        await rootCA.signCACertificateRequest(signedCert2, (result2 as { csrPath: string }).csrPath, { validity: 3650 });
        await intermediateCA2.installCACertificate(signedCert2);
    });

    it("T8a - Root CA should have a self-signed certificate", async () => {
        fs.existsSync(rootCA.caCertificate).should.eql(true);
        const rootDer = await readCertificateChainAsync(rootCA.caCertificate);
        const rootInfo = exploreCertificate(rootDer[0]);

        // Root CA: issuer == subject
        (rootInfo.tbsCertificate.issuer.commonName ?? "").should.eql("Test Root CA");
        (rootInfo.tbsCertificate.subject.commonName ?? "").should.eql("Test Root CA");
    });

    it("T8b - Intermediate CAs should be signed by Root CA", async () => {
        // Intermediate CA #1
        const int1Der = await readCertificateChainAsync(intermediateCA1.caCertificate);
        const int1Info = exploreCertificate(int1Der[0]);
        (int1Info.tbsCertificate.subject.commonName ?? "").should.eql("Intermediate CA 1");
        (int1Info.tbsCertificate.issuer.commonName ?? "").should.eql("Test Root CA");

        // Intermediate CA #2
        const int2Der = await readCertificateChainAsync(intermediateCA2.caCertificate);
        const int2Info = exploreCertificate(int2Der[0]);
        (int2Info.tbsCertificate.subject.commonName ?? "").should.eql("Intermediate CA 2");
        (int2Info.tbsCertificate.issuer.commonName ?? "").should.eql("Test Root CA");
    });

    it("T8c - End-entity cert signed by Intermediate CA #1 should have full chain", async () => {
        // Generate end-entity key + CSR
        const endEntityManager = new CertificateManager({
            location: path.join(testData.tmpFolder, "EndEntity1")
        });
        await endEntityManager.initialize();

        const csrFile = await endEntityManager.createCertificateRequest({
            applicationUri: "urn:test:hierarchy:app1",
            dns: ["app1.example.com"],
            subject: "/CN=App1",
            validity: 365
        });

        // Sign with Intermediate CA #1
        const certFile = path.join(testData.tmpFolder, "app1_cert.pem");
        await intermediateCA1.signCertificateRequest(certFile, csrFile, {
            validity: 365
        });

        // The signed cert file contains full chain: end-entity + intermediate + root
        const chain = await readCertificateChainAsync(certFile);
        chain.length.should.eql(3, "chain = end-entity + intermediate + root CA");

        // Element 0: end-entity cert issued by Intermediate CA 1
        const endEntityInfo = exploreCertificate(chain[0]);
        (endEntityInfo.tbsCertificate.subject.commonName ?? "").should.eql("App1");
        (endEntityInfo.tbsCertificate.issuer.commonName ?? "").should.eql("Intermediate CA 1");

        // Element 1: Intermediate CA 1 cert issued by Root CA
        const intCAInfo = exploreCertificate(chain[1]);
        (intCAInfo.tbsCertificate.subject.commonName ?? "").should.eql("Intermediate CA 1");
        (intCAInfo.tbsCertificate.issuer.commonName ?? "").should.eql("Test Root CA");

        // Element 2: Root CA cert (self-signed, last in chain per Part 6 §6.2.6)
        const rootInfo = exploreCertificate(chain[2]);
        (rootInfo.tbsCertificate.subject.commonName ?? "").should.eql("Test Root CA");
        (rootInfo.tbsCertificate.issuer.commonName ?? "").should.eql("Test Root CA");

        await endEntityManager.dispose();
    });

    it("T8d - generateKeyPairAndSignDER from Intermediate CA #2 should produce full chain", async () => {
        const result = await intermediateCA2.generateKeyPairAndSignDER({
            applicationUri: "urn:test:hierarchy:app2",
            dns: ["app2.example.com"],
            subject: "/CN=App2",
            validity: 365
        });

        Buffer.isBuffer(result.certificateDer).should.eql(true);
        should.exist(result.privateKey);

        // Full chain: end-entity + intermediate + root
        const elements = split_der(result.certificateDer);
        elements.length.should.eql(3, "chain = end-entity + intermediate + root CA");

        // Verify issuer chain: App2 -> Intermediate CA 2 -> Test Root CA
        const endEntityInfo = exploreCertificate(elements[0]);
        (endEntityInfo.tbsCertificate.subject.commonName ?? "").should.eql("App2");
        (endEntityInfo.tbsCertificate.issuer.commonName ?? "").should.eql("Intermediate CA 2");

        const intCAInfo = exploreCertificate(elements[1]);
        (intCAInfo.tbsCertificate.subject.commonName ?? "").should.eql("Intermediate CA 2");
        (intCAInfo.tbsCertificate.issuer.commonName ?? "").should.eql("Test Root CA");

        const rootInfo = exploreCertificate(elements[2]);
        (rootInfo.tbsCertificate.subject.commonName ?? "").should.eql("Test Root CA");
        (rootInfo.tbsCertificate.issuer.commonName ?? "").should.eql("Test Root CA");

        // Certificate and private key should match
        certificateMatchesPrivateKey(result.certificateDer, result.privateKey).should.eql(true);
    });

    it("T8e - lifecycle: restart after install returns status 'ready'", async () => {
        // Simulate restart: new object, same directory
        const restartedCA = new CertificateAuthority({
            keySize: 2048,
            location: path.join(testData.tmpFolder, "IntermediateCA1"),
            subject: "/CN=Intermediate CA 1/O=TestOrg"
        });

        const result = await restartedCA.initializeCSR();
        result.status.should.eql("ready", "restart after install → ready");

        // The restarted CA can still sign certificates
        const signed = await restartedCA.generateKeyPairAndSignDER({
            applicationUri: "urn:test:hierarchy:restart",
            dns: ["restart.example.com"],
            subject: "/CN=RestartApp",
            validity: 365
        });
        Buffer.isBuffer(signed.certificateDer).should.eql(true);
        const info = exploreCertificate(signed.certificateDer);
        (info.tbsCertificate.issuer.commonName ?? "").should.eql("Intermediate CA 1");
    });

    it("T8f - lifecycle: restart before install returns status 'pending'", async () => {
        // Create a fresh intermediate CA — initializeCSR but do NOT install cert
        const pendingCA = new CertificateAuthority({
            keySize: 2048,
            location: path.join(testData.tmpFolder, "PendingCA"),
            subject: "/CN=Pending CA/O=TestOrg"
        });
        const firstResult = await pendingCA.initializeCSR();
        firstResult.status.should.eql("created");

        // Simulate restart: new object, same directory, cert NOT installed
        const restartedCA = new CertificateAuthority({
            keySize: 2048,
            location: path.join(testData.tmpFolder, "PendingCA"),
            subject: "/CN=Pending CA/O=TestOrg"
        });
        const secondResult = await restartedCA.initializeCSR();
        secondResult.status.should.eql("pending", "restart before install → pending");
        // The CSR path should be the same as the first call
        if (secondResult.status === "pending" && firstResult.status === "created") {
            path.basename(secondResult.csrPath).should.eql(path.basename(firstResult.csrPath));
        }
    });

    it("T8g - renewCSR() should return 'expired' when threshold exceeds remaining validity", async () => {
        // Use a huge threshold so the cert always appears "about to expire"
        const result = await intermediateCA1.renewCSR(999999);
        result.status.should.eql("expired");
        if (result.status === "expired") {
            // The CSR should be regenerated for renewal
            fs.existsSync(result.csrPath).should.eql(true);
            // expiryDate should be a Date in the future (cert was valid)
            result.expiryDate.should.be.instanceOf(Date);
        }
    });

    it("T8h - renewCSR() should return 'ready' when cert is not close to expiry", async () => {
        // With threshold = 0 days, the cert should not be considered expiring
        const result = await intermediateCA1.renewCSR(0);
        result.status.should.eql("ready");
    });

    it("T8i - full runtime renewal flow: renewCSR → sign → install → sign cert", async () => {
        // Step 1: detect expiry (use huge threshold to trigger)
        const renewResult = await intermediateCA1.renewCSR(999999);
        renewResult.status.should.eql("expired");
        if (renewResult.status !== "expired") return;

        // Step 2: Root CA re-signs the CSR (output includes chain)
        const renewedCert = path.join(testData.tmpFolder, "int1_renewed.pem");
        await rootCA.signCACertificateRequest(renewedCert, renewResult.csrPath, { validity: 3650 });

        // Step 3: install the renewed certificate chain
        const installResult = await intermediateCA1.installCACertificate(renewedCert);
        installResult.status.should.eql("success");

        // Step 4: verify the renewed CA can sign end-entity certs
        const result = await intermediateCA1.generateKeyPairAndSignDER({
            applicationUri: "urn:test:hierarchy:renewed",
            dns: ["renewed.example.com"],
            subject: "/CN=RenewedApp",
            validity: 365
        });
        Buffer.isBuffer(result.certificateDer).should.eql(true);

        const info = exploreCertificate(result.certificateDer);
        (info.tbsCertificate.issuer.commonName ?? "").should.eql("Intermediate CA 1");

        // Step 5: after renewal, initializeCSR should return "ready"
        const postRenewal = await intermediateCA1.initializeCSR();
        postRenewal.status.should.eql("ready");
    });

    it("T8j - verify full trust chain: end-entity → intermediate → root", async () => {
        // Sign a cert with intermediate CA #1
        const result = await intermediateCA1.generateKeyPairAndSignDER({
            applicationUri: "urn:test:hierarchy:chain",
            dns: ["chain.example.com"],
            subject: "/CN=ChainApp",
            validity: 365
        });

        // Full chain per OPC UA Part 6 §6.2.6
        const elements = split_der(result.certificateDer);
        elements.length.should.eql(3, "complete chain = end-entity + intermediate + root");

        // Link 1: end-entity issued by intermediate CA
        const endEntityInfo = exploreCertificate(elements[0]);
        (endEntityInfo.tbsCertificate.issuer.commonName ?? "").should.eql("Intermediate CA 1");

        // Link 2: intermediate CA issued by root CA
        const intermediateInfo = exploreCertificate(elements[1]);
        (intermediateInfo.tbsCertificate.subject.commonName ?? "").should.eql("Intermediate CA 1");
        (intermediateInfo.tbsCertificate.issuer.commonName ?? "").should.eql("Test Root CA");

        // Link 3: root CA is self-signed (last in chain per Part 6 §6.2.6)
        const rootInfo = exploreCertificate(elements[2]);
        (rootInfo.tbsCertificate.subject.commonName ?? "").should.eql("Test Root CA");
        (rootInfo.tbsCertificate.issuer.commonName ?? "").should.eql("Test Root CA");
    });
});

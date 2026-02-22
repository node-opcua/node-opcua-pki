import fs from "node:fs";
import path from "node:path";
import "should";

import {
    certificateMatchesPrivateKey,
    convertPEMtoDER,
    exploreCertificate,
    identifyDERContent,
    makeSHA1Thumbprint,
    readCertificate,
    readPrivateKey
} from "node-opcua-crypto";
import {
    CertificateAuthority,
    CertificateManager,
    convertPFXtoPEM,
    createPFX,
    dumpPFX,
    extractAllFromPFX,
    extractCACertificatesFromPFX,
    extractCertificateFromPFX,
    extractPrivateKeyFromPFX
} from "node-opcua-pki";
import { beforeTest } from "./helpers";

describe("PFX (PKCS#12) Toolbox", function () {
    const testData = beforeTest(this);

    let certFile: string;
    let keyFile: string;
    let caCertFile: string;
    let pfxFile: string;
    let pfxFileWithPassword: string;
    let pfxFileWithCA: string;

    before(async () => {
        // Set up a CA + CertificateManager to create real certs
        const caLocation = path.join(testData.tmpFolder, "PFX_CA");
        const ca = new CertificateAuthority({
            keySize: 2048,
            location: caLocation
        });
        await ca.initialize();

        caCertFile = ca.caCertificate;

        // Create a CertificateManager to get a self-signed cert + key
        const cmLocation = path.join(testData.tmpFolder, "PFX_CM");
        const cm = new CertificateManager({ location: cmLocation });
        await cm.initialize();

        await cm.createSelfSignedCertificate({
            applicationUri: "urn:test:pfx",
            subject: "CN=PFXTest",
            dns: ["localhost"],
            startDate: new Date(),
            validity: 365
        });

        certFile = path.join(cm.rootDir, "own/certs/self_signed_certificate.pem");
        keyFile = cm.privateKey;
        pfxFile = path.join(testData.tmpFolder, "test.pfx");
        pfxFileWithPassword = path.join(testData.tmpFolder, "test_with_password.pfx");
        pfxFileWithCA = path.join(testData.tmpFolder, "test_with_ca.pfx");

        await cm.dispose();
    });

    // ── createPFX ──────────────────────────────────────────────

    describe("createPFX", () => {
        it("should create a PFX file without password", async () => {
            await createPFX({
                certificateFile: certFile,
                privateKeyFile: keyFile,
                outputFile: pfxFile
            });

            fs.existsSync(pfxFile).should.be.true("PFX file should exist");
            const stat = fs.statSync(pfxFile);
            stat.size.should.be.greaterThan(0, "PFX file should not be empty");

            // The raw file should be a valid PKCS#12 DER structure
            const raw = fs.readFileSync(pfxFile);
            identifyDERContent(raw).should.eql("PKCS12", "PFX should be identified as PKCS12");
        });

        it("should create a PFX file with a password", async () => {
            await createPFX({
                certificateFile: certFile,
                privateKeyFile: keyFile,
                outputFile: pfxFileWithPassword,
                passphrase: "Secret123!"
            });

            fs.existsSync(pfxFileWithPassword).should.be.true("PFX file should exist");
            const raw = fs.readFileSync(pfxFileWithPassword);
            identifyDERContent(raw).should.eql("PKCS12");
        });

        it("should create a PFX file with CA certificates", async () => {
            await createPFX({
                certificateFile: certFile,
                privateKeyFile: keyFile,
                outputFile: pfxFileWithCA,
                caCertificateFiles: [caCertFile]
            });

            fs.existsSync(pfxFileWithCA).should.be.true("PFX file with CA should exist");
            const raw = fs.readFileSync(pfxFileWithCA);
            identifyDERContent(raw).should.eql("PKCS12");
            // PFX with CA should be larger than PFX without
            raw.length.should.be.greaterThan(fs.readFileSync(pfxFile).length, "PFX with CA certs should be larger than without");
        });
    });

    // ── extractCertificateFromPFX ──────────────────────────────

    describe("extractCertificateFromPFX", () => {
        it("should extract the certificate and it should match the original", async () => {
            const pem = await extractCertificateFromPFX({ pfxFile });

            pem.should.containEql("BEGIN CERTIFICATE");
            pem.should.containEql("END CERTIFICATE");

            // Parse the extracted PEM back to DER and compare
            // thumbprints with the original
            const extractedDer = convertPEMtoDER(pem);
            const originalCert = readCertificate(certFile);
            const originalThumbprint = makeSHA1Thumbprint(originalCert).toString("hex");
            const extractedThumbprint = makeSHA1Thumbprint(extractedDer).toString("hex");

            extractedThumbprint.should.eql(originalThumbprint, "extracted certificate thumbprint should match the original");
        });

        it("should extract the certificate from a password-protected PFX", async () => {
            const pem = await extractCertificateFromPFX({
                pfxFile: pfxFileWithPassword,
                passphrase: "Secret123!"
            });

            pem.should.containEql("BEGIN CERTIFICATE");
            pem.should.containEql("END CERTIFICATE");

            // Verify subject matches original
            const extractedDer = convertPEMtoDER(pem);
            const extractedInfo = exploreCertificate(extractedDer);
            const originalInfo = exploreCertificate(readCertificate(certFile));

            const extractedCN = extractedInfo.tbsCertificate.subject.commonName || "";
            const originalCN = originalInfo.tbsCertificate.subject.commonName || "";
            extractedCN.should.eql(originalCN, "subject CN should match");
        });

        it("should fail to extract with the wrong password", async () => {
            let threw = false;
            try {
                await extractCertificateFromPFX({
                    pfxFile: pfxFileWithPassword,
                    passphrase: "WrongPassword"
                });
            } catch (_e) {
                threw = true;
            }
            threw.should.be.true("should throw when using wrong passphrase");
        });
    });

    // ── extractPrivateKeyFromPFX ───────────────────────────────

    describe("extractPrivateKeyFromPFX", () => {
        it("should extract the private key and it should match the certificate", async () => {
            const keyPem = await extractPrivateKeyFromPFX({ pfxFile });
            const certPem = await extractCertificateFromPFX({ pfxFile });

            keyPem.should.containEql("PRIVATE KEY");

            // Verify the extracted private key matches the extracted cert
            const certDer = convertPEMtoDER(certPem);
            const privateKey = readPrivateKey(keyFile);
            certificateMatchesPrivateKey(certDer, privateKey).should.be.true("private key should match the certificate");
        });

        it("should extract the private key from a password-protected PFX", async () => {
            const pem = await extractPrivateKeyFromPFX({
                pfxFile: pfxFileWithPassword,
                passphrase: "Secret123!"
            });

            pem.should.containEql("PRIVATE KEY");
        });

        it("should fail to extract key with wrong password", async () => {
            let threw = false;
            try {
                await extractPrivateKeyFromPFX({
                    pfxFile: pfxFileWithPassword,
                    passphrase: "Wrong"
                });
            } catch (_e) {
                threw = true;
            }
            threw.should.be.true("should throw with wrong passphrase");
        });
    });

    // ── extractCACertificatesFromPFX ───────────────────────────

    describe("extractCACertificatesFromPFX", () => {
        it("should return CA certs that match the original CA", async () => {
            const pem = await extractCACertificatesFromPFX({ pfxFile: pfxFileWithCA });

            pem.should.containEql("BEGIN CERTIFICATE");

            // The extracted CA cert thumbprint must match the original
            const extractedCaDer = convertPEMtoDER(pem);
            const originalCaCert = readCertificate(caCertFile);
            const originalCaThumbprint = makeSHA1Thumbprint(originalCaCert).toString("hex");
            const extractedCaThumbprint = makeSHA1Thumbprint(extractedCaDer).toString("hex");

            extractedCaThumbprint.should.eql(originalCaThumbprint, "extracted CA certificate thumbprint should match the original");
        });

        it("should return no CA certs for a PFX without CA", async () => {
            const pem = await extractCACertificatesFromPFX({ pfxFile });

            // No CA certs were bundled, so no CERTIFICATE block expected
            pem.should.not.containEql("BEGIN CERTIFICATE");
        });
    });

    // ── extractAllFromPFX ──────────────────────────────────────

    describe("extractAllFromPFX", () => {
        it("should extract all parts and each should be valid", async () => {
            const result = await extractAllFromPFX({ pfxFile });

            result.certificate.should.containEql("BEGIN CERTIFICATE");
            result.privateKey.should.containEql("PRIVATE KEY");

            // Verify certificate subject
            const certDer = convertPEMtoDER(result.certificate);
            const info = exploreCertificate(certDer);
            const cn = info.tbsCertificate.subject.commonName || "";
            cn.should.eql("PFXTest");
        });

        it("should extract all parts from PFX with CA certs", async () => {
            const result = await extractAllFromPFX({ pfxFile: pfxFileWithCA });

            result.certificate.should.containEql("BEGIN CERTIFICATE");
            result.privateKey.should.containEql("PRIVATE KEY");
            result.caCertificates.should.containEql("BEGIN CERTIFICATE");

            // Verify the leaf cert is not the same as the CA cert
            const leafDer = convertPEMtoDER(result.certificate);
            const caDer = convertPEMtoDER(result.caCertificates);
            const leafThumb = makeSHA1Thumbprint(leafDer).toString("hex");
            const caThumb = makeSHA1Thumbprint(caDer).toString("hex");
            leafThumb.should.not.eql(caThumb, "leaf and CA should be different certs");
        });
    });

    // ── convertPFXtoPEM ────────────────────────────────────────

    describe("convertPFXtoPEM", () => {
        it("should create a combined PEM with cert + key", async () => {
            const pemFile = path.join(testData.tmpFolder, "combined.pem");

            await convertPFXtoPEM(pfxFile, pemFile);

            fs.existsSync(pemFile).should.be.true("Combined PEM should exist");
            const content = fs.readFileSync(pemFile, "utf-8");
            content.should.containEql("BEGIN CERTIFICATE");
            content.should.containEql("PRIVATE KEY");

            // Count the number of certificate blocks — should be exactly 1
            // for a PFX without CA certs
            const certBlocks = content.match(/BEGIN CERTIFICATE/g) || [];
            certBlocks.length.should.eql(1, "should contain exactly 1 certificate");
        });

        it("should create a combined PEM from password-protected PFX", async () => {
            const pemFile = path.join(testData.tmpFolder, "combined_pwd.pem");

            await convertPFXtoPEM(pfxFileWithPassword, pemFile, "Secret123!");

            fs.existsSync(pemFile).should.be.true();
            const content = fs.readFileSync(pemFile, "utf-8");
            content.should.containEql("BEGIN CERTIFICATE");
            content.should.containEql("PRIVATE KEY");
        });

        it("should include CA certs in the combined PEM", async () => {
            const pemFile = path.join(testData.tmpFolder, "combined_ca.pem");

            await convertPFXtoPEM(pfxFileWithCA, pemFile);

            const content = fs.readFileSync(pemFile, "utf-8");
            // Should contain at least 2 certificates (leaf + CA)
            const certBlocks = content.match(/BEGIN CERTIFICATE/g) || [];
            certBlocks.length.should.be.greaterThan(1, "should contain leaf cert + CA cert(s)");
        });
    });

    // ── dumpPFX ────────────────────────────────────────────────

    describe("dumpPFX", () => {
        it("should return a human-readable info dump", async () => {
            const output = await dumpPFX(pfxFile);

            output.length.should.be.greaterThan(0, "dump should not be empty");
        });

        it("should dump a password-protected PFX", async () => {
            const output = await dumpPFX(pfxFileWithPassword, "Secret123!");

            output.length.should.be.greaterThan(0);
        });
    });

    // ── Round-trip verification ────────────────────────────────

    describe("round-trip", () => {
        it("should preserve certificate identity through PFX round-trip", async () => {
            // Read the original certificate
            const originalCert = readCertificate(certFile);
            const originalInfo = exploreCertificate(originalCert);
            const originalThumbprint = makeSHA1Thumbprint(originalCert).toString("hex");

            // Extract from PFX
            const extractedPem = await extractCertificateFromPFX({ pfxFile });
            const extractedDer = convertPEMtoDER(extractedPem);
            const extractedInfo = exploreCertificate(extractedDer);
            const extractedThumbprint = makeSHA1Thumbprint(extractedDer).toString("hex");

            // Verify thumbprints match exactly
            extractedThumbprint.should.eql(originalThumbprint, "thumbprints must match");

            // Verify subjects match
            const extractedCN = extractedInfo.tbsCertificate.subject.commonName || "";
            const originalCN = originalInfo.tbsCertificate.subject.commonName || "";
            extractedCN.should.eql(originalCN, "subject CN must match");

            // Verify serial numbers match
            extractedInfo.tbsCertificate.serialNumber.should.eql(
                originalInfo.tbsCertificate.serialNumber,
                "serial numbers must match"
            );

            // Verify validity dates match
            extractedInfo.tbsCertificate.validity.notBefore
                .toISOString()
                .should.eql(originalInfo.tbsCertificate.validity.notBefore.toISOString(), "notBefore dates must match");
            extractedInfo.tbsCertificate.validity.notAfter
                .toISOString()
                .should.eql(originalInfo.tbsCertificate.validity.notAfter.toISOString(), "notAfter dates must match");
        });

        it("should preserve private key through PFX round-trip", async () => {
            // Read the original private key
            const originalKey = readPrivateKey(keyFile);

            // Create PFX and extract
            const extractedCertPem = await extractCertificateFromPFX({ pfxFile });
            const extractedCertDer = convertPEMtoDER(extractedCertPem);

            // The original private key must still match the
            // extracted certificate
            certificateMatchesPrivateKey(extractedCertDer, originalKey).should.be.true(
                "original private key must match the certificate extracted from PFX"
            );
        });
    });
});

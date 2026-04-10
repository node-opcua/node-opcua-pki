/**
 * TDD tests for certificate chain preservation.
 *
 * These tests verify that:
 * 1. `#moveCertificate` preserves the certificate chain on disk
 * 2. Legacy "buggy" PEM files (single block, concatenated DER) are
 *    auto-healed on startup
 * 3. `addTrustedCertificateFromChain` writes the full chain to disk
 * 4. Round-trip persistence survives dispose/re-create cycles
 */

import fs from "node:fs";
import path from "node:path";
import "should";
import {
    type Certificate,
    makeSHA1Thumbprint,
    readCertificateChain,
    readCertificateRevocationList,
    toPem
} from "node-opcua-crypto";
import { CertificateAuthority, CertificateManager, isIssuer, type KeySize, VerificationStatus } from "node-opcua-pki";
import { beforeTest } from "./helpers";

// ── Helpers ────────────────────────────────────────────────────

/**
 * Reproduce the historical buggy `toPem` behaviour (pre-v5.3.4):
 * wraps the entire concatenated DER buffer in a single PEM block.
 */
function toPemBuggy(buffer: Buffer, pemType: string): string {
    const b = buffer.toString("base64");
    const strBody = b.match(/.{1,64}/g)?.join("\n") || "";
    return `-----BEGIN ${pemType}-----\n${strBody}\n-----END ${pemType}-----\n`;
}

/**
 * Count the number of `-----BEGIN CERTIFICATE-----` blocks in a
 * PEM string.
 */
function countPemBlocks(pem: string): number {
    const matches = pem.match(/-----BEGIN CERTIFICATE-----/g);
    return matches ? matches.length : 0;
}

// ════════════════════════════════════════════════════════════════
// Test Suite
// ════════════════════════════════════════════════════════════════

describe("Certificate Chain Preservation", function (this: Mocha.Suite) {
    const testData = beforeTest(this);

    // ── Shared CA hierarchy ────────────────────────────────────
    let rootCA: CertificateAuthority;
    let rootCACertFilename: string;
    let rootCACrlFilename: string;
    let caCert: Certificate;
    let caCrl: Buffer;

    let counter = 0;
    const prefix = `chainPres_${Date.now()}`;

    before(async () => {
        rootCA = new CertificateAuthority({
            keySize: 2048 as KeySize,
            location: path.join(testData.tmpFolder, "CHAIN_PRES_CA")
        });
        await rootCA.initialize();
        await rootCA.constructCACertificateWithCRL();
        rootCACertFilename = rootCA.caCertificate;
        rootCACrlFilename = rootCA.revocationList;
        caCert = readCertificateChain(rootCACertFilename)[0];
        caCrl = await readCertificateRevocationList(rootCACrlFilename);
    });

    after(async () => {
        await CertificateManager.disposeAll();
    });

    async function makeCM(
        folderName?: string,
        extraOpts?: Partial<ConstructorParameters<typeof CertificateManager>[0]>
    ): Promise<CertificateManager> {
        const location = path.join(testData.tmpFolder, folderName ?? `${prefix}_${counter++}`);
        const cm = new CertificateManager({ location, ...extraOpts });
        await cm.initialize();
        return cm;
    }

    async function createCASigned(cm: CertificateManager, appUri: string, subject: string): Promise<string> {
        const csrFile = await cm.createCertificateRequest({
            applicationUri: appUri,
            subject,
            dns: ["localhost"],
            startDate: new Date(),
            validity: 365
        });
        const signedFile = path.join(testData.tmpFolder, `chainPres_signed_${counter++}.pem`);
        await rootCA.signCertificateRequest(signedFile, csrFile, {
            applicationUri: appUri,
            startDate: new Date(),
            validity: 365
        });
        return signedFile;
    }

    // ──────────────────────────────────────────────────────────
    // Group 1: #moveCertificate chain preservation
    // ──────────────────────────────────────────────────────────
    describe("Group 1 — #moveCertificate chain preservation", () => {
        let cm: CertificateManager;
        let leafCert: Certificate;

        before(async () => {
            cm = await makeCM();
            // Add CA as issuer with CRL so verifyCertificate works
            await cm.addIssuer(caCert);
            await cm.addRevocationList(caCrl, "issuers");

            const helperCM = await makeCM();
            const signedFile = await createCASigned(helperCM, "urn:test:chain-pres-move", "CN=ChainPresMove");
            leafCert = readCertificateChain(signedFile)[0];
            await helperCM.dispose();
        });

        after(async () => {
            await cm.dispose();
        });

        it("1a - trustCertificate with chain should write full chain to PEM file", async () => {
            const chain = [leafCert, caCert];
            await cm.trustCertificate(chain);

            // Find the PEM file in trusted/certs/
            const files = await fs.promises.readdir(cm.trustedFolder);
            files.length.should.be.greaterThan(0, "trusted folder should have files");

            const pemContent = await fs.promises.readFile(path.join(cm.trustedFolder, files[files.length - 1]), "utf-8");
            const blockCount = countPemBlocks(pemContent);
            blockCount.should.eql(2, "PEM file should contain 2 certificate blocks (leaf + CA)");
        });

        it("1b - reject then trust (move) should preserve chain in PEM file", async () => {
            const cm2 = await makeCM();
            await cm2.addIssuer(caCert);
            await cm2.addRevocationList(caCrl, "issuers");

            const chain = [leafCert, caCert];

            // First reject with chain
            await cm2.rejectCertificate(chain);

            // Now trust (move from rejected → trusted)
            await cm2.trustCertificate(chain);

            // The file should now be in trusted/certs/
            const files = await fs.promises.readdir(cm2.trustedFolder);
            files.length.should.be.greaterThan(0);

            const pemContent = await fs.promises.readFile(path.join(cm2.trustedFolder, files[files.length - 1]), "utf-8");
            const blockCount = countPemBlocks(pemContent);
            blockCount.should.eql(2, "After move, PEM should still contain 2 blocks");

            await cm2.dispose();
        });

        it("1c - trustCertificate with single cert should write 1 block (no regression)", async () => {
            const cm3 = await makeCM();
            await cm3.createSelfSignedCertificate({
                applicationUri: "urn:test:single-cert-regression",
                subject: "CN=SingleCert",
                dns: ["localhost"],
                startDate: new Date(),
                validity: 365
            });
            const certFile = path.join(cm3.rootDir, "own/certs/self_signed_certificate.pem");
            const cert = readCertificateChain(certFile)[0];
            await cm3.trustCertificate(cert);

            const files = await fs.promises.readdir(cm3.trustedFolder);
            files.length.should.be.greaterThan(0);

            const pemContent = await fs.promises.readFile(path.join(cm3.trustedFolder, files[files.length - 1]), "utf-8");
            countPemBlocks(pemContent).should.eql(1, "Single cert should produce 1 PEM block");

            await cm3.dispose();
        });
    });

    // ──────────────────────────────────────────────────────────
    // Group 2: Legacy PEM migration
    // ──────────────────────────────────────────────────────────
    describe("Group 2 — Legacy PEM migration in #scanCertFolder", () => {
        it("2a - buggy PEM with concatenated DER should be rewritten as proper multi-block PEM", async () => {
            const folderName = `${prefix}_legacy_2a`;
            const location = path.join(testData.tmpFolder, folderName);

            // Pre-create the PKI structure
            const cmSetup = await makeCM(folderName);
            await cmSetup.addIssuer(caCert);
            await cmSetup.addRevocationList(caCrl, "issuers");

            // Create a CA-signed cert to get a real leaf
            const helperCM = await makeCM();
            const signedFile = await createCASigned(helperCM, "urn:test:legacy-2a", "CN=Legacy2a");
            const leafCert = readCertificateChain(signedFile)[0];
            await helperCM.dispose();
            await cmSetup.dispose();

            // Write a "buggy" PEM: single block containing [leaf + CA]
            const concatenatedDer = Buffer.concat([leafCert, caCert]);
            const buggyPem = toPemBuggy(concatenatedDer, "CERTIFICATE");

            // Verify the buggy PEM has exactly 1 block
            countPemBlocks(buggyPem).should.eql(1, "buggy PEM should have exactly 1 block");

            const buggyFilename = path.join(location, "trusted/certs", "legacy_buggy_cert.pem");
            await fs.promises.writeFile(buggyFilename, buggyPem, "ascii");

            // Now create a new CM at the same location — it should
            // scan and heal the buggy PEM
            const cm2 = new CertificateManager({ location });
            await cm2.initialize();

            // Read the file back — it should now have 2 proper blocks
            const healedPem = await fs.promises.readFile(buggyFilename, "utf-8");
            countPemBlocks(healedPem).should.eql(2, "healed PEM should have 2 proper certificate blocks");

            await cm2.dispose();
        });

        it("2b - buggy PEM with [leaf, intermediate CA] should auto-register the CA in issuers store", async () => {
            const folderName = `${prefix}_legacy_2b`;
            const location = path.join(testData.tmpFolder, folderName);

            // Pre-create structure
            const cmSetup = await makeCM(folderName);
            await cmSetup.dispose();

            // Create a CA-signed cert
            const helperCM = await makeCM();
            const signedFile = await createCASigned(helperCM, "urn:test:legacy-2b", "CN=Legacy2b");
            const leafCert = readCertificateChain(signedFile)[0];
            await helperCM.dispose();

            // Write buggy PEM with [leaf, CA] in trusted folder
            const concatenatedDer = Buffer.concat([leafCert, caCert]);
            const buggyPem = toPemBuggy(concatenatedDer, "CERTIFICATE");
            const buggyFilename = path.join(location, "trusted/certs", "legacy_with_ca.pem");
            await fs.promises.writeFile(buggyFilename, buggyPem, "ascii");

            // Re-open CM
            const cm2 = new CertificateManager({ location });
            await cm2.initialize();

            // Verify the CA cert is now in the issuers store
            const caThumbprint = makeSHA1Thumbprint(caCert).toString("hex");
            const hasIt = await cm2.hasIssuer(caThumbprint);
            hasIt.should.be.true("CA cert from legacy PEM should be auto-registered as issuer");

            await cm2.dispose();
        });

        it("2c - buggy PEM with [leaf, non-CA cert] should NOT register the non-CA in issuers", async () => {
            const folderName = `${prefix}_legacy_2c`;
            const location = path.join(testData.tmpFolder, folderName);

            // Create structure
            const cmSetup = await makeCM(folderName);
            await cmSetup.dispose();

            // Create two CA-signed leaf certs (non-CA, non-self-signed)
            const helperCM1 = await makeCM();
            const signedFile1 = await createCASigned(helperCM1, "urn:test:legacy-2c-leaf1", "CN=Leaf2cA");
            const leafCert1 = readCertificateChain(signedFile1)[0];
            await helperCM1.dispose();

            const helperCM2 = await makeCM();
            const signedFile2 = await createCASigned(helperCM2, "urn:test:legacy-2c-leaf2", "CN=Leaf2cB");
            const leafCert2 = readCertificateChain(signedFile2)[0];
            await helperCM2.dispose();

            // Neither cert is a CA
            isIssuer(leafCert1).should.be.false("leafCert1 should not be a CA");
            isIssuer(leafCert2).should.be.false("leafCert2 should not be a CA");

            // Write buggy PEM with [leafCert1, leafCert2]
            const concatenatedDer = Buffer.concat([leafCert1, leafCert2]);
            const buggyPem = toPemBuggy(concatenatedDer, "CERTIFICATE");
            const buggyFilename = path.join(location, "trusted/certs", "legacy_noca.pem");
            await fs.promises.writeFile(buggyFilename, buggyPem, "ascii");

            // Re-open
            const cm3 = new CertificateManager({ location });
            await cm3.initialize();

            // leafCert2 should NOT be in issuers (it's not a CA)
            const otherThumbprint = makeSHA1Thumbprint(leafCert2).toString("hex");
            const hasIt = await cm3.hasIssuer(otherThumbprint);
            hasIt.should.be.false("non-CA cert should NOT be registered as issuer");

            await cm3.dispose();
        });

        it("2d - normal single-cert PEM should NOT be rewritten", async () => {
            const folderName = `${prefix}_legacy_2d`;
            const location = path.join(testData.tmpFolder, folderName);

            const cmSetup = await makeCM(folderName);
            await cmSetup.createSelfSignedCertificate({
                applicationUri: "urn:test:legacy-2d",
                subject: "CN=Normal2d",
                dns: ["localhost"],
                startDate: new Date(),
                validity: 365
            });
            const certFile = path.join(cmSetup.rootDir, "own/certs/self_signed_certificate.pem");
            const singleCert = readCertificateChain(certFile)[0];
            await cmSetup.dispose();

            // Write a normal PEM to trusted/certs/
            const normalPem = toPem(singleCert, "CERTIFICATE");
            const normalFilename = path.join(location, "trusted/certs", "normal_cert.pem");
            await fs.promises.writeFile(normalFilename, normalPem, "ascii");

            // Record mtime
            const statBefore = await fs.promises.stat(normalFilename);

            // Small delay to ensure mtime would differ if file is rewritten
            await new Promise((r) => setTimeout(r, 100));

            // Re-open
            const cm2 = new CertificateManager({ location });
            await cm2.initialize();

            const statAfter = await fs.promises.stat(normalFilename);

            // File should NOT have been rewritten
            statAfter.mtimeMs.should.eql(statBefore.mtimeMs, "normal single-cert PEM should not be rewritten");

            await cm2.dispose();
        });
    });

    // ──────────────────────────────────────────────────────────
    // Group 3: addTrustedCertificateFromChain chain on disk
    // ──────────────────────────────────────────────────────────
    describe("Group 3 — addTrustedCertificateFromChain chain on disk", () => {
        it("3a - addTrustedCertificateFromChain should write the full chain to the trusted PEM", async () => {
            const cm = await makeCM(undefined, {
                addCertificateValidationOptions: {
                    ignoreMissingRevocationList: true
                }
            });
            await cm.addIssuer(caCert);
            await cm.addRevocationList(caCrl, "issuers");

            const helperCM = await makeCM();
            const signedFile = await createCASigned(helperCM, "urn:test:chain-disk-3a", "CN=ChainDisk3a");
            const leafCert = readCertificateChain(signedFile)[0];
            await helperCM.dispose();

            // Provide [leaf, CA] as chain
            const chain = [leafCert, caCert];
            const status = await cm.addTrustedCertificateFromChain(chain);
            status.should.eql(VerificationStatus.Good);

            // Read the trusted PEM file
            const files = await fs.promises.readdir(cm.trustedFolder);
            files.length.should.be.greaterThan(0);

            // Find the file that corresponds to our leaf
            let foundChainFile = false;
            for (const f of files) {
                const pemContent = await fs.promises.readFile(path.join(cm.trustedFolder, f), "utf-8");
                if (countPemBlocks(pemContent) >= 2) {
                    foundChainFile = true;
                    break;
                }
            }
            foundChainFile.should.be.true("trusted folder should have a PEM file with >= 2 blocks");

            await cm.dispose();
        });

        it("3b - after addTrustedCertificateFromChain, verifyCertificate should still work", async () => {
            const cm = await makeCM(undefined, {
                addCertificateValidationOptions: {
                    ignoreMissingRevocationList: true
                }
            });
            await cm.addIssuer(caCert);
            await cm.addRevocationList(caCrl, "issuers");

            const helperCM = await makeCM();
            const signedFile = await createCASigned(helperCM, "urn:test:chain-disk-3b", "CN=ChainDisk3b");
            const leafCert = readCertificateChain(signedFile)[0];
            await helperCM.dispose();

            const chain = [leafCert, caCert];
            const addStatus = await cm.addTrustedCertificateFromChain(chain);
            addStatus.should.eql(VerificationStatus.Good);

            // Now verify the leaf alone
            const verifyStatus = await cm.verifyCertificate(leafCert, {
                ignoreMissingRevocationList: true
            });
            verifyStatus.should.eql(VerificationStatus.Good);

            await cm.dispose();
        });
    });

    // ──────────────────────────────────────────────────────────
    // Group 4: Round-trip persistence
    // ──────────────────────────────────────────────────────────
    describe("Group 4 — Round-trip persistence", () => {
        it("4a - trust a chain, dispose, re-create → leaf should still be trusted", async () => {
            const folderName = `${prefix}_roundtrip_4a`;
            const cm1 = await makeCM(folderName);
            await cm1.addIssuer(caCert);
            await cm1.addRevocationList(caCrl, "issuers");

            const helperCM = await makeCM();
            const signedFile = await createCASigned(helperCM, "urn:test:roundtrip-4a", "CN=RoundTrip4a");
            const leafCert = readCertificateChain(signedFile)[0];
            await helperCM.dispose();

            await cm1.trustCertificate([leafCert, caCert]);
            await cm1.dispose();

            // Re-create at the same location
            const location = path.join(testData.tmpFolder, folderName);
            const cm2 = new CertificateManager({ location });
            await cm2.initialize();

            const trustStatus = await cm2.isCertificateTrusted(leafCert);
            trustStatus.should.eql("Good", "leaf should still be trusted after restart");

            await cm2.dispose();
        });

        it("4b - legacy buggy PEM → dispose → re-create → file healed + leaf trusted + issuer registered", async () => {
            const folderName = `${prefix}_roundtrip_4b`;
            const location = path.join(testData.tmpFolder, folderName);

            // Create structure
            const cmSetup = await makeCM(folderName);
            await cmSetup.dispose();

            // Create a leaf cert
            const helperCM = await makeCM();
            const signedFile = await createCASigned(helperCM, "urn:test:roundtrip-4b", "CN=RoundTrip4b");
            const leafCert = readCertificateChain(signedFile)[0];
            await helperCM.dispose();

            // Write buggy PEM
            const concatenatedDer = Buffer.concat([leafCert, caCert]);
            const buggyPem = toPemBuggy(concatenatedDer, "CERTIFICATE");
            const buggyFilename = path.join(location, "trusted/certs", "legacy_roundtrip.pem");
            await fs.promises.writeFile(buggyFilename, buggyPem, "ascii");

            // First boot: heals the file
            const cm1 = new CertificateManager({ location });
            await cm1.initialize();

            const healedPem1 = await fs.promises.readFile(buggyFilename, "utf-8");
            countPemBlocks(healedPem1).should.eql(2, "first boot should heal to 2 blocks");

            const leafTrusted = await cm1.isCertificateTrusted(leafCert);
            leafTrusted.should.eql("Good", "leaf should be trusted after heal");

            const caThumb = makeSHA1Thumbprint(caCert).toString("hex");
            (await cm1.hasIssuer(caThumb)).should.be.true("CA should be in issuers after heal");

            await cm1.dispose();

            // Second boot: file is already healed, should NOT change
            const cm2 = new CertificateManager({ location });
            await cm2.initialize();

            const healedPem2 = await fs.promises.readFile(buggyFilename, "utf-8");
            countPemBlocks(healedPem2).should.eql(2, "second boot should keep 2 blocks");
            healedPem2.should.eql(healedPem1, "second boot should not modify the file");

            const leafTrusted2 = await cm2.isCertificateTrusted(leafCert);
            leafTrusted2.should.eql("Good", "leaf should still be trusted");

            (await cm2.hasIssuer(caThumb)).should.be.true("CA should still be in issuers");

            await cm2.dispose();
        });
    });
});

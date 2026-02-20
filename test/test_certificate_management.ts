import fs from "node:fs";
import path from "node:path";
import "should";

import { makeSHA1Thumbprint, readCertificate } from "node-opcua-crypto";
import { CertificateManager, type CertificateManagerOptions } from "node-opcua-pki";
import { beforeTest } from "./helpers";

describe("CertificateManager - hasIssuer, removeTrustedCertificate, removeIssuer, removeRevocationListsForIssuer", function () {
    const testData = beforeTest(this);

    let cm: CertificateManager;

    const caCertFilename = path.join(__dirname, "fixtures/CTT_sample_certificates/CA/certs/ctt_ca1I.der");
    const crlFilename = path.join(__dirname, "fixtures/CTT_sample_certificates/CA/crl/ctt_ca1I.crl");

    // A second cert to use as a "trusted application certificate"
    const _appCertFilename = path.join(__dirname, "fixtures/CTT_sample_certificates/CA/certs/ctt_ca1I.der");

    beforeEach(async () => {
        const location = path.join(testData.tmpFolder, `cert_mgmt_${Date.now()}`);
        const options: CertificateManagerOptions = { location };
        cm = new CertificateManager(options);
        await cm.initialize();
    });

    afterEach(async () => {
        await cm.dispose();
    });

    // ── hasIssuer ────────────────────────────────────────────────

    describe("hasIssuer", () => {
        it("should return false when no issuers have been added", async () => {
            const result = await cm.hasIssuer("0000000000000000000000000000000000000000");
            result.should.be.false();
        });

        it("should return true after an issuer is added", async () => {
            const caCert = readCertificate(caCertFilename);
            await cm.addIssuer(caCert);

            const thumbprint = makeSHA1Thumbprint(caCert).toString("hex");
            const result = await cm.hasIssuer(thumbprint);
            result.should.be.true();
        });

        it("should return true regardless of thumbprint case", async () => {
            const caCert = readCertificate(caCertFilename);
            await cm.addIssuer(caCert);

            const thumbprint = makeSHA1Thumbprint(caCert).toString("hex");
            // Test with uppercase
            (await cm.hasIssuer(thumbprint.toUpperCase())).should.be.true();
            // Test with lowercase
            (await cm.hasIssuer(thumbprint.toLowerCase())).should.be.true();
        });

        it("should return false for a trusted certificate thumbprint", async () => {
            const cert = readCertificate(caCertFilename);
            await cm.trustCertificate(cert);

            const thumbprint = makeSHA1Thumbprint(cert).toString("hex");
            // It's trusted, not an issuer
            (await cm.hasIssuer(thumbprint)).should.be.false();
        });
    });

    // ── removeTrustedCertificate ─────────────────────────────────

    describe("removeTrustedCertificate", () => {
        it("should return null when thumbprint is not found", async () => {
            const result = await cm.removeTrustedCertificate("0000000000000000000000000000000000000000");
            (result === null).should.be.true();
        });

        it("should remove a trusted certificate and return its buffer", async () => {
            const cert = readCertificate(caCertFilename);
            await cm.trustCertificate(cert);

            const thumbprint = makeSHA1Thumbprint(cert).toString("hex");

            // Verify it's trusted
            const statusBefore = await cm.getCertificateStatus(cert);
            statusBefore.should.eql("trusted");

            // Remove it
            const removed = await cm.removeTrustedCertificate(thumbprint);
            (removed !== null).should.be.true("should return the certificate buffer");

            // Verify file no longer exists in trusted folder
            const trustedFiles = fs.readdirSync(cm.trustedFolder);
            const matching = trustedFiles.filter((f) => {
                const ext = path.extname(f).toLowerCase();
                return ext === ".pem" || ext === ".der";
            });
            // The cert should not be found by its thumbprint anymore
            let found = false;
            for (const file of matching) {
                try {
                    const c = readCertificate(path.join(cm.trustedFolder, file));
                    if (makeSHA1Thumbprint(c).toString("hex") === thumbprint) {
                        found = true;
                    }
                } catch (_e) {
                    // ignore
                }
            }
            found.should.be.false("certificate file should have been deleted");
        });

        it("should not affect issuer certificates", async () => {
            const cert = readCertificate(caCertFilename);
            await cm.addIssuer(cert);

            const thumbprint = makeSHA1Thumbprint(cert).toString("hex");

            // Try removing as trusted — should not find it
            const result = await cm.removeTrustedCertificate(thumbprint);
            (result === null).should.be.true("issuer cert should not be found in trusted");

            // Issuer should still exist
            (await cm.hasIssuer(thumbprint)).should.be.true();
        });
    });

    // ── removeIssuer ─────────────────────────────────────────────

    describe("removeIssuer", () => {
        it("should return null when thumbprint is not found", async () => {
            const result = await cm.removeIssuer("0000000000000000000000000000000000000000");
            (result === null).should.be.true();
        });

        it("should remove an issuer and return its buffer", async () => {
            const caCert = readCertificate(caCertFilename);
            await cm.addIssuer(caCert);

            const thumbprint = makeSHA1Thumbprint(caCert).toString("hex");
            (await cm.hasIssuer(thumbprint)).should.be.true();

            const removed = await cm.removeIssuer(thumbprint);
            (removed !== null).should.be.true("should return the certificate buffer");

            // Verify it's gone from the index
            (await cm.hasIssuer(thumbprint)).should.be.false();

            // Verify file no longer exists in issuers/certs
            const issuerFiles = fs.readdirSync(cm.issuersCertFolder);
            let found = false;
            for (const file of issuerFiles) {
                const ext = path.extname(file).toLowerCase();
                if (ext === ".pem" || ext === ".der") {
                    try {
                        const c = readCertificate(path.join(cm.issuersCertFolder, file));
                        if (makeSHA1Thumbprint(c).toString("hex") === thumbprint) {
                            found = true;
                        }
                    } catch (_e) {
                        // ignore
                    }
                }
            }
            found.should.be.false("issuer cert file should have been deleted");
        });

        it("should not affect trusted certificates", async () => {
            const cert = readCertificate(caCertFilename);
            await cm.trustCertificate(cert);

            const thumbprint = makeSHA1Thumbprint(cert).toString("hex");

            // Try removing as issuer — should not find it
            const result = await cm.removeIssuer(thumbprint);
            (result === null).should.be.true("trusted cert should not be found in issuers");

            // Trusted cert should still exist
            const status = await cm.getCertificateStatus(cert);
            status.should.eql("trusted");
        });
    });

    // ── removeRevocationListsForIssuer ──────────────────────────

    describe("removeRevocationListsForIssuer", () => {
        it("should not fail when no CRLs exist", async () => {
            const caCert = readCertificate(caCertFilename);
            // No CRLs added — should not throw
            await cm.removeRevocationListsForIssuer(caCert);
        });

        it("should remove CRLs from issuers/crl for a given issuer", async () => {
            const caCert = readCertificate(caCertFilename);
            await cm.addIssuer(caCert);

            const crl = fs.readFileSync(crlFilename);
            await cm.addRevocationList(crl, "issuers");

            // Verify CRL exists
            const before = fs.readdirSync(cm.issuersCrlFolder).filter((f) => f.endsWith(".pem") || f.endsWith(".crl"));
            before.length.should.be.greaterThan(0);

            // Remove CRLs for this issuer
            await cm.removeRevocationListsForIssuer(caCert, "issuers");

            // Verify CRL is gone
            const after = fs.readdirSync(cm.issuersCrlFolder).filter((f) => f.endsWith(".pem") || f.endsWith(".crl"));
            after.length.should.eql(0, "CRL files should have been deleted");
        });

        it("should remove CRLs from trusted/crl for a given issuer", async () => {
            const caCert = readCertificate(caCertFilename);
            await cm.addIssuer(caCert);

            const crl = fs.readFileSync(crlFilename);
            await cm.addRevocationList(crl, "trusted");

            // Verify CRL exists
            const before = fs.readdirSync(cm.crlFolder).filter((f) => f.endsWith(".pem") || f.endsWith(".crl"));
            before.length.should.be.greaterThan(0);

            // Remove CRLs for this issuer from trusted only
            await cm.removeRevocationListsForIssuer(caCert, "trusted");

            // Verify trusted CRL is gone
            const after = fs.readdirSync(cm.crlFolder).filter((f) => f.endsWith(".pem") || f.endsWith(".crl"));
            after.length.should.eql(0, "trusted CRL files should have been deleted");
        });

        it("should remove CRLs from both folders with target 'all'", async () => {
            const caCert = readCertificate(caCertFilename);
            await cm.addIssuer(caCert);

            const crl = fs.readFileSync(crlFilename);
            await cm.addRevocationList(crl, "issuers");
            await cm.addRevocationList(crl, "trusted");

            // Both folders should have CRLs
            fs.readdirSync(cm.issuersCrlFolder)
                .filter((f) => f.endsWith(".pem") || f.endsWith(".crl"))
                .length.should.be.greaterThan(0);
            fs.readdirSync(cm.crlFolder)
                .filter((f) => f.endsWith(".pem") || f.endsWith(".crl"))
                .length.should.be.greaterThan(0);

            // Remove all CRLs for this issuer
            await cm.removeRevocationListsForIssuer(caCert, "all");

            // Both folders should be empty
            fs.readdirSync(cm.issuersCrlFolder)
                .filter((f) => f.endsWith(".pem") || f.endsWith(".crl"))
                .length.should.eql(0, "issuers/crl should be empty");
            fs.readdirSync(cm.crlFolder)
                .filter((f) => f.endsWith(".pem") || f.endsWith(".crl"))
                .length.should.eql(0, "trusted/crl should be empty");
        });

        it("should only remove CRLs for the specified issuer, not others", async () => {
            const caCert = readCertificate(caCertFilename);
            await cm.addIssuer(caCert);

            const crl = fs.readFileSync(crlFilename);
            await cm.addRevocationList(crl, "issuers");

            // Create a dummy certificate that is different from caCert
            // to test that removeRevocationListsForIssuer doesn't remove
            // CRLs for unrelated issuers
            await cm.createSelfSignedCertificate({
                applicationUri: "urn:test:dummy",
                subject: "CN=DummyIssuer",
                dns: ["localhost"],
                startDate: new Date(),
                validity: 365
            });

            // CRL for the original CA should still exist before removal
            const before = fs.readdirSync(cm.issuersCrlFolder).filter((f) => f.endsWith(".pem") || f.endsWith(".crl"));
            before.length.should.be.greaterThan(0);

            // Use self-signed cert (own cert) as the "other issuer" —
            // removeRevocationListsForIssuer with this cert should NOT
            // remove the caCert's CRL
            const ownCertFile = path.join(cm.rootDir, "own/certs/self_signed_certificate.pem");
            const ownCert = readCertificate(ownCertFile);
            await cm.removeRevocationListsForIssuer(ownCert, "issuers");

            // CRL for original CA should still be there
            const after = fs.readdirSync(cm.issuersCrlFolder).filter((f) => f.endsWith(".pem") || f.endsWith(".crl"));
            after.length.should.be.greaterThan(0, "CRL for original CA should not be removed");
        });
    });

    // ── addTrustedCertificateFromChain ───────────────────────────

    describe("addTrustedCertificateFromChain", () => {
        it("should accept and trust a valid single certificate", async () => {
            // Use the CA cert as a stand-in for a valid single cert
            const cert = readCertificate(caCertFilename);

            const status = await cm.addTrustedCertificateFromChain(cert);
            status.should.eql("Good");
        });

        it("should reject a corrupt certificate buffer", async () => {
            const badBuffer = Buffer.from("this is not a certificate");
            const status = await cm.addTrustedCertificateFromChain(badBuffer);
            status.should.not.eql("Good");
        });

        it("should trust a self-signed certificate", async () => {
            // Create a self-signed cert first
            await cm.createSelfSignedCertificate({
                applicationUri: "urn:test:self-signed",
                subject: "CN=TestSelfSigned",
                dns: ["localhost"],
                startDate: new Date(),
                validity: 365
            });

            const ownCertFile = path.join(cm.rootDir, "own/certs/self_signed_certificate.pem");
            const ownCert = readCertificate(ownCertFile);

            const status = await cm.addTrustedCertificateFromChain(ownCert);
            status.should.eql("Good");

            // Verify it's now trusted
            const trustedStatus = await cm._checkRejectedOrTrusted(ownCert);
            trustedStatus.should.eql("trusted");
        });

        it("should not modify the issuer store when trusting a leaf certificate", async () => {
            // Pre-add the CA as an issuer
            const caCert = readCertificate(caCertFilename);
            await cm.addIssuer(caCert);

            const caThumbprint = makeSHA1Thumbprint(caCert).toString("hex");
            (await cm.hasIssuer(caThumbprint)).should.be.true("issuer should exist before");

            // Trust a self-signed cert via addTrustedCertificateFromChain
            await cm.createSelfSignedCertificate({
                applicationUri: "urn:test:no-side-effect",
                subject: "CN=NoSideEffect",
                dns: ["localhost"],
                startDate: new Date(),
                validity: 365,
            });
            const ownCertFile = path.join(cm.rootDir, "own/certs/self_signed_certificate.pem");
            const ownCert = readCertificate(ownCertFile);

            const status = await cm.addTrustedCertificateFromChain(ownCert);
            status.should.eql("Good");

            // Issuer must still be present — no side effects
            (await cm.hasIssuer(caThumbprint)).should.be.true("issuer should still exist after");

            // Rejected folder should be empty — no side effects
            const rejectedFiles = fs.readdirSync(cm.rejectedFolder).filter(
                (f) => f.endsWith(".pem") || f.endsWith(".der")
            );
            rejectedFiles.length.should.eql(0, "rejected folder should be empty");
        });
    });

    // ── isIssuerInUseByTrustedCertificate ────────────────────────

    describe("isIssuerInUseByTrustedCertificate", () => {
        it("should return false when no certificates are trusted", async () => {
            const caCert = readCertificate(caCertFilename);
            const result = await cm.isIssuerInUseByTrustedCertificate(caCert);
            result.should.be.false();
        });

        it("should return false when issuer is not related to trusted certs", async () => {
            // Create and trust a self-signed cert (not signed by caCert)
            await cm.createSelfSignedCertificate({
                applicationUri: "urn:test:independent",
                subject: "CN=Independent",
                dns: ["localhost"],
                startDate: new Date(),
                validity: 365
            });
            const ownCertFile = path.join(cm.rootDir, "own/certs/self_signed_certificate.pem");
            const ownCert = readCertificate(ownCertFile);
            await cm.trustCertificate(ownCert);

            // caCert did not sign ownCert
            const caCert = readCertificate(caCertFilename);
            const result = await cm.isIssuerInUseByTrustedCertificate(caCert);
            result.should.be.false();
        });

        it("should return true when issuer signed a trusted certificate", async () => {
            const caCert = readCertificate(caCertFilename);
            await cm.addIssuer(caCert);

            // Find a user certificate signed by this CA from the fixtures
            const userCertFilename = path.join(__dirname, "fixtures/CTT_sample_certificates/CA/certs/ctt_ca1I_usrT.der");
            if (fs.existsSync(userCertFilename)) {
                const userCert = readCertificate(userCertFilename);
                await cm.trustCertificate(userCert);

                const result = await cm.isIssuerInUseByTrustedCertificate(caCert);
                result.should.be.true();
            }
        });
    });
});

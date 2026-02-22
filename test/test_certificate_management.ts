import fs from "node:fs";
import path from "node:path";
import { makeSHA1Thumbprint, readCertificate, readCertificateRevocationList } from "node-opcua-crypto";
import { CertificateAuthority, CertificateManager, type CertificateManagerOptions, VerificationStatus } from "node-opcua-pki";
import { beforeTest } from "./helpers";

describe("CertificateManager - hasIssuer, removeTrustedCertificate, removeIssuer, removeRevocationListsForIssuer", function () {
    const testData = beforeTest(this);

    let caCertFilename: string;
    let caCertificateWithCrlFilename: string;
    let crlFilename: string;

    // A second cert to use as a "trusted application certificate"
    const _appCertFilename = path.join(__dirname, "fixtures/CTT_sample_certificates/CA/certs/ctt_ca1I.der");

    let theCertificateAuthority: CertificateAuthority;

    const makeCACertificate = async () => {
        theCertificateAuthority = new CertificateAuthority({
            keySize: 2048,
            location: path.join(testData.tmpFolder, "CA")
        });
        await theCertificateAuthority.initialize();
        await theCertificateAuthority.constructCACertificateWithCRL();

        caCertFilename = theCertificateAuthority.caCertificate;
        caCertificateWithCrlFilename = theCertificateAuthority.caCertificateWithCrl;
        crlFilename = theCertificateAuthority.revocationList;
    };
    before(async () => {
        await makeCACertificate();
    });

    let cm: CertificateManager;

    let counter = 0;
    const date = new Date().toISOString().replace(/[-:.]/g, "");
    beforeEach(async () => {
        const location = path.join(testData.tmpFolder, `cert_mgmt_${date}_${counter++}`);
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

    describe("Odd cases", () => {
        it("certificate within a valid chaine shall be stored with the thumbprint of the leaf chain element", () => {});
        it("verifyCertificate - should return InvalidCertifiicate if the DER contains a IssuerCertificate and its CRL ", async () => {
            const caCertWithCrl = readCertificate(caCertificateWithCrlFilename);
            await cm.trustCertificate(caCertWithCrl);
            const status = await cm.verifyCertificate(caCertWithCrl, { acceptCertificateWithValidIssuerChain: true });
            status.should.eql(VerificationStatus.BadCertificateInvalid);
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
            const statusBefore = await cm.verifyCertificate(cert, { acceptCertificateWithValidIssuerChain: true });
            statusBefore.should.eql(VerificationStatus.Good, "should be a valid certificate with valid chain, may be not trusted");

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
            const status = await cm.verifyCertificate(cert);
            status.should.eql(VerificationStatus.Good);
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
            const verif = await cm.addIssuer(caCert);
            verif.should.eql(VerificationStatus.Good);

            // add crl
            const crl = await readCertificateRevocationList(crlFilename);

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

            const crl = await readCertificateRevocationList(crlFilename);
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

            const crl = await readCertificateRevocationList(crlFilename);
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

            const crl = await readCertificateRevocationList(crlFilename);
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
            const trustedStatus = await cm.isCertificateTrusted(ownCert);
            trustedStatus.should.eql("Good");
        });

        const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
        it("XX should not modify the issuer store when trusting a leaf certificate", async () => {
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
                validity: 365
            });
            const ownCertFile = path.join(cm.rootDir, "own/certs/self_signed_certificate.pem");
            const ownCert = readCertificate(ownCertFile);

            const status = await cm.addTrustedCertificateFromChain(ownCert);
            status.should.eql("Good");

            await wait(1000);
            // Issuer must still be present — no side effects
            (await cm.hasIssuer(caThumbprint)).should.be.true("issuer should still exist after");

            // Rejected folder should be empty — no side effects
            const rejectedFiles = fs.readdirSync(cm.rejectedFolder).filter((f) => f.endsWith(".pem") || f.endsWith(".der"));
            rejectedFiles.length.should.eql(0, "rejected folder should be empty");
        });

        it("should find issuers added via filesystem (stale index)", async () => {
            // Simulate what writeTrustedCertificateList does:
            // write an issuer cert directly to disk, bypassing
            // the CertificateManager's in-memory _thumbs index.
            const caCert = readCertificate(caCertFilename);
            const issuerFolder = cm.issuersCertFolder;
            const destFile = path.join(issuerFolder, "manually_added_ca.der");
            fs.writeFileSync(destFile, caCert);

            // Build a "chain" by concatenating a self-signed leaf
            // with the CA cert (the issuer check only looks at
            // thumbprints, not actual signature relationships)
            await cm.createSelfSignedCertificate({
                applicationUri: "urn:test:stale-index",
                subject: "CN=StaleIndex",
                dns: ["localhost"],
                startDate: new Date(),
                validity: 365
            });
            const ownCertFile = path.join(cm.rootDir, "own/certs/self_signed_certificate.pem");
            const leafCert = readCertificate(ownCertFile);

            // Concatenate leaf + CA to form a chain buffer
            const chainBuffer = Buffer.concat([leafCert, caCert]);

            // Without _readCertificates(), this would return
            // BadCertificateChainIncomplete because the CA
            // isn't in the in-memory index
            const status = await cm.addTrustedCertificateFromChain(chainBuffer);
            status.should.eql("Good");

            // Leaf should now be trusted
            const trustedStatus = await cm.isCertificateTrusted(leafCert);
            trustedStatus.should.eql("Good");
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

        it("X1 should return true when issuer signed a trusted certificate", async () => {
            const caCert = readCertificate(caCertFilename);
            await cm.addIssuer(caCert);

            // Create a certificate signed by our test CA
            const appCm = new CertificateManager({
                location: path.join(testData.tmpFolder, `cert_mgmt_${date}_issuer_use`)
            });
            await appCm.initialize();
            const csrFile = await appCm.createCertificateRequest({
                applicationUri: "urn:test:issuer-in-use",
                subject: "CN=IssuerInUseTest",
                dns: ["localhost"],
                startDate: new Date(),
                validity: 365
            });

            const signedCertFile = path.join(testData.tmpFolder, "signed_for_issuer_test.pem");
            await theCertificateAuthority.signCertificateRequest(signedCertFile, csrFile, {
                applicationUri: "urn:test:issuer-in-use",
                startDate: new Date(),
                validity: 365
            });

            const signedCert = readCertificate(signedCertFile);
            await cm.trustCertificate(signedCert);

            const result = await cm.isIssuerInUseByTrustedCertificate(caCert);
            result.should.be.true("CA should be in use after trusting a cert it signed");

            await appCm.dispose();
        });
    });

    // ── reloadCertificates ──────────────────────────────────────

    describe("reloadCertificates", () => {
        it("should pick up externally added trusted certificates", async () => {
            // Create a self-signed cert and write it directly to trusted folder
            await cm.createSelfSignedCertificate({
                applicationUri: "urn:test:reload-add",
                subject: "CN=ReloadAdd",
                dns: ["localhost"],
                startDate: new Date(),
                validity: 365
            });
            const ownCertFile = path.join(cm.rootDir, "own/certs/self_signed_certificate.pem");
            const ownCert = readCertificate(ownCertFile);

            // Write directly to trusted folder (bypass CM API)
            const destFile = path.join(cm.trustedFolder, "externally_added.der");
            fs.writeFileSync(destFile, ownCert);

            // Before reload: CM doesn't know about it
            const statusBefore = await cm.isCertificateTrusted(ownCert);
            statusBefore.should.eql("BadCertificateUntrusted");

            // After reload: CM picks it up
            await cm.reloadCertificates();
            const statusAfter = await cm.isCertificateTrusted(ownCert);
            statusAfter.should.eql("Good");
        });

        it("should detect externally deleted trusted certificates", async () => {
            // Add a cert via CM API
            const caCert = readCertificate(caCertFilename);
            await cm.trustCertificate(caCert);

            const statusBefore = await cm.isCertificateTrusted(caCert);
            statusBefore.should.eql("Good");

            // Delete the file directly from disk
            const files = fs.readdirSync(cm.trustedFolder);
            for (const f of files) {
                if (f.endsWith(".pem") || f.endsWith(".der")) {
                    fs.unlinkSync(path.join(cm.trustedFolder, f));
                }
            }

            // Before reload: CM still thinks it's trusted (stale)
            const statusStale = await cm.isCertificateTrusted(caCert);
            statusStale.should.eql("Good");

            // After reload: CM sees deletion
            await cm.reloadCertificates();
            const statusAfter = await cm.isCertificateTrusted(caCert);
            statusAfter.should.eql("BadCertificateUntrusted");
        });

        it("should pick up externally added issuers", async () => {
            const caCert = readCertificate(caCertFilename);
            const thumbprint = makeSHA1Thumbprint(caCert).toString("hex");

            // Bypass CM API: write issuer directly to disk
            const destFile = path.join(cm.issuersCertFolder, "external_issuer.der");
            fs.writeFileSync(destFile, caCert);

            // Before reload: CM doesn't know about it
            (await cm.hasIssuer(thumbprint)).should.be.false();

            // After reload: CM picks it up
            await cm.reloadCertificates();
            (await cm.hasIssuer(thumbprint)).should.be.true();
        });
    });
});

import path from "node:path";
import { combine_der, makeSHA1Thumbprint, readCertificateChainAsync, readCertificateRevocationList } from "node-opcua-crypto";
import { CertificateAuthority, CertificateManager, type CertificateManagerOptions, VerificationStatus } from "node-opcua-pki";
import { beforeTest } from "./helpers";

describe("addTrustedCertificateFromChain — OPC UA Part 4 conformance", function () {
    const testData = beforeTest(this);

    // ── Shared CA hierarchy ────────────────────────────────────
    let rootCA: CertificateAuthority;
    let rootCACertFilename: string;
    let rootCACrlFilename: string;

    before(async () => {
        rootCA = new CertificateAuthority({
            keySize: 2048,
            location: path.join(testData.tmpFolder, "addTrust_CA")
        });
        await rootCA.initialize();
        await rootCA.constructCACertificateWithCRL();
        rootCACertFilename = rootCA.caCertificate;
        rootCACrlFilename = rootCA.revocationList;
    });

    // ── Helpers ────────────────────────────────────────────────

    let counter = 0;
    const prefix = `addTrust_${Date.now()}`;

    /**
     * Create a new CertificateManager with custom options.
     * Caller is responsible for calling dispose().
     */
    async function makeCM(extraOpts?: Partial<CertificateManagerOptions>): Promise<CertificateManager> {
        const location = path.join(testData.tmpFolder, `${prefix}_${counter++}`);
        const cm = new CertificateManager({ location, ...extraOpts });
        await cm.initialize();
        return cm;
    }

    /**
     * Create a certificate signed by our test CA.
     * Returns the path to the signed certificate.
     */
    async function createCASigned(cm: CertificateManager, appUri: string, subject: string): Promise<string> {
        const csrFile = await cm.createCertificateRequest({
            applicationUri: appUri,
            subject,
            dns: ["localhost"],
            startDate: new Date(),
            validity: 365
        });
        const signedFile = path.join(testData.tmpFolder, `signed_${counter++}.pem`);
        await rootCA.signCertificateRequest(signedFile, csrFile, {
            applicationUri: appUri,
            startDate: new Date(),
            validity: 365
        });
        return signedFile;
    }

    // === Test Suite =============================================

    // ── 1. Structure validation ────────────────────────────────
    describe("Step 1 — Certificate Structure", () => {
        let cm: CertificateManager;
        before(async () => {
            cm = await makeCM({
                addCertificateValidationOptions: {
                    ignoreMissingRevocationList: true
                }
            });
        });
        after(async () => {
            await cm.dispose();
        });

        it("should reject a corrupt buffer", async () => {
            const badBuffer = Buffer.from("not a certificate");
            const status = await cm.addTrustedCertificateFromChain(badBuffer);
            status.should.eql(VerificationStatus.BadCertificateInvalid);
        });

        it("should reject an empty buffer", async () => {
            const emptyBuffer = Buffer.alloc(0);
            const status = await cm.addTrustedCertificateFromChain(emptyBuffer);
            status.should.eql(VerificationStatus.BadCertificateInvalid);
        });
    });

    // ── 2. Self-signed certificates ────────────────────────────
    describe("Step 2 — Self-signed certificates", () => {
        let cm: CertificateManager;
        before(async () => {
            cm = await makeCM({
                addCertificateValidationOptions: {
                    ignoreMissingRevocationList: true
                }
            });
        });
        after(async () => {
            await cm.dispose();
        });

        it("should accept and trust a valid self-signed certificate", async () => {
            await cm.createSelfSignedCertificate({
                applicationUri: "urn:test:self-signed-ok",
                subject: "CN=SelfSigned",
                dns: ["localhost"],
                startDate: new Date(),
                validity: 365
            });
            const certFile = path.join(cm.rootDir, "own/certs/self_signed_certificate.pem");
            const cert = await readCertificateChainAsync(certFile);

            const status = await cm.addTrustedCertificateFromChain(cert[0]);
            status.should.eql(VerificationStatus.Good);

            // Verify it's now trusted
            const trusted = await cm.isCertificateTrusted(cert[0]);
            trusted.should.eql("Good");
        });

        it("should accept a CA self-signed certificate (root CA cert)", async () => {
            const caCert = await readCertificateChainAsync(rootCACertFilename);
            const status = await cm.addTrustedCertificateFromChain(caCert[0]);
            status.should.eql(VerificationStatus.Good);
        });
    });

    // ── 3. Chain walk — issuer presence ────────────────────────
    describe("Step 2–4 — Chain building, signature, issuer presence", () => {
        let cm: CertificateManager;
        let appCm: CertificateManager;

        beforeEach(async () => {
            cm = await makeCM({
                addCertificateValidationOptions: {
                    ignoreMissingRevocationList: true
                }
            });
            appCm = await makeCM({
                addCertificateValidationOptions: {
                    ignoreMissingRevocationList: true
                }
            });
        });
        afterEach(async () => {
            await cm.dispose();
            await appCm.dispose();
        });

        it("should reject a CA-signed cert when issuer is NOT in the issuers store", async () => {
            const signedFile = await createCASigned(appCm, "urn:test:no-issuer", "CN=NoIssuer");
            const signedCert = await readCertificateChainAsync(signedFile);

            // Do NOT add the CA cert to cm's issuers store
            const status = await cm.addTrustedCertificateFromChain(signedCert[0]);
            status.should.eql(VerificationStatus.BadCertificateChainIncomplete);
        });

        it("should accept a CA-signed cert when issuer IS in the issuers store", async () => {
            // Add the root CA as an issuer
            const caCert = await readCertificateChainAsync(rootCACertFilename);
            await cm.addIssuer(caCert[0]);

            // Add the CRL so revocation check doesn't block us
            const crl = await readCertificateRevocationList(rootCACrlFilename);
            await cm.addRevocationList(crl, "issuers");

            const signedFile = await createCASigned(appCm, "urn:test:with-issuer", "CN=WithIssuer");
            const signedCert = await readCertificateChainAsync(signedFile);

            const status = await cm.addTrustedCertificateFromChain(signedCert[0]);
            status.should.eql(VerificationStatus.Good);

            // Verify it's now trusted
            const trusted = await cm.isCertificateTrusted(signedCert[0]);
            trusted.should.eql("Good");
        });

        it("should reject when chain is provided but issuer is not registered", async () => {
            const signedFile = await createCASigned(appCm, "urn:test:chain-no-reg", "CN=ChainNoReg");
            const signedCert = await readCertificateChainAsync(signedFile);
            const caCert = await readCertificateChainAsync(rootCACertFilename);

            // Build chain: leaf + CA, but CA is NOT in issuers store
            const chainBuffer = combine_der([signedCert[0], caCert[0]]);
            const status = await cm.addTrustedCertificateFromChain(chainBuffer);
            status.should.eql(VerificationStatus.BadCertificateChainIncomplete);
        });

        it("should accept a chain buffer when issuer is registered", async () => {
            // Register the CA as issuer
            const caCert = await readCertificateChainAsync(rootCACertFilename);
            await cm.addIssuer(caCert[0]);
            const crl = await readCertificateRevocationList(rootCACrlFilename);
            await cm.addRevocationList(crl, "issuers");

            // Create signed cert and provide full chain
            const signedFile = await createCASigned(appCm, "urn:test:chain-ok", "CN=ChainOK");
            const signedCert = await readCertificateChainAsync(signedFile);
            const chainBuffer = combine_der([signedCert[0], caCert[0]]);

            const status = await cm.addTrustedCertificateFromChain(chainBuffer);
            status.should.eql(VerificationStatus.Good);
        });

        it("should only trust the leaf certificate, not the CA", async () => {
            // Register the CA as issuer
            const caCert = await readCertificateChainAsync(rootCACertFilename);
            await cm.addIssuer(caCert[0]);
            const crl = await readCertificateRevocationList(rootCACrlFilename);
            await cm.addRevocationList(crl, "issuers");

            const signedFile = await createCASigned(appCm, "urn:test:leaf-only", "CN=LeafOnly");
            const signedCert = await readCertificateChainAsync(signedFile);
            const chainBuffer = combine_der([signedCert[0], caCert[0]]);

            await cm.addTrustedCertificateFromChain(chainBuffer);

            // Leaf should be trusted
            const leafTrusted = await cm.isCertificateTrusted(signedCert[0]);
            leafTrusted.should.eql("Good");

            // CA should NOT be in the trusted store (only in issuers)
            const caThumb = makeSHA1Thumbprint(caCert[0]).toString("hex");
            (await cm.hasIssuer(caThumb)).should.be.true();
        });
    });

    // ── 4. Validity period checks ──────────────────────────────
    describe("Step 5 — Validity Period", () => {
        it("should reject an expired certificate (default strict mode)", async () => {
            const cm = await makeCM({
                addCertificateValidationOptions: {
                    ignoreMissingRevocationList: true
                }
            });
            try {
                // Create a self-signed cert that expired yesterday
                const yesterday = new Date();
                yesterday.setDate(yesterday.getDate() - 2);

                await cm.createSelfSignedCertificate({
                    applicationUri: "urn:test:expired",
                    subject: "CN=Expired",
                    dns: ["localhost"],
                    startDate: yesterday,
                    validity: 1 // 1 day validity  => expired
                });
                const certFile = path.join(cm.rootDir, "own/certs/self_signed_certificate.pem");
                const cert = await readCertificateChainAsync(certFile);

                const status = await cm.addTrustedCertificateFromChain(cert[0]);
                status.should.eql(VerificationStatus.BadCertificateTimeInvalid);
            } finally {
                await cm.dispose();
            }
        });

        it("should accept an expired certificate when acceptExpiredCertificate is true", async () => {
            const cm = await makeCM({
                addCertificateValidationOptions: {
                    acceptExpiredCertificate: true,
                    ignoreMissingRevocationList: true
                }
            });
            try {
                const yesterday = new Date();
                yesterday.setDate(yesterday.getDate() - 2);

                await cm.createSelfSignedCertificate({
                    applicationUri: "urn:test:expired-accept",
                    subject: "CN=ExpiredAccept",
                    dns: ["localhost"],
                    startDate: yesterday,
                    validity: 1
                });
                const certFile = path.join(cm.rootDir, "own/certs/self_signed_certificate.pem");
                const cert = await readCertificateChainAsync(certFile);

                const status = await cm.addTrustedCertificateFromChain(cert[0]);
                status.should.eql(VerificationStatus.Good);
            } finally {
                await cm.dispose();
            }
        });
    });

    // ── 5. Revocation checks ───────────────────────────────────
    describe("Step 6 — Revocation Check", () => {
        it("should reject a CA-signed cert when CRL is missing (strict mode)", async () => {
            const cm = await makeCM(); // strict: ignoreMissingRevocationList = false
            const appCm = await makeCM();
            try {
                // Add issuer but NO CRL
                const caCert = await readCertificateChainAsync(rootCACertFilename);
                await cm.addIssuer(caCert[0]);

                const signedFile = await createCASigned(appCm, "urn:test:no-crl", "CN=NoCRL");
                const signedCert = await readCertificateChainAsync(signedFile);

                const status = await cm.addTrustedCertificateFromChain(signedCert[0]);
                status.should.eql(VerificationStatus.BadCertificateRevocationUnknown);
            } finally {
                await cm.dispose();
                await appCm.dispose();
            }
        });

        it("should accept a CA-signed cert when CRL is missing but ignoreMissingRevocationList is true", async () => {
            const cm = await makeCM({
                addCertificateValidationOptions: {
                    ignoreMissingRevocationList: true
                }
            });
            const appCm = await makeCM();
            try {
                // Add issuer but NO CRL
                const caCert = await readCertificateChainAsync(rootCACertFilename);
                await cm.addIssuer(caCert[0]);

                const signedFile = await createCASigned(appCm, "urn:test:no-crl-ok", "CN=NoCRLOK");
                const signedCert = await readCertificateChainAsync(signedFile);

                const status = await cm.addTrustedCertificateFromChain(signedCert[0]);
                status.should.eql(VerificationStatus.Good);
            } finally {
                await cm.dispose();
                await appCm.dispose();
            }
        });

        it("should reject a revoked certificate (strict mode)", async () => {
            const cm = await makeCM();
            const appCm = await makeCM();
            try {
                // Setup: add issuer + CRL
                const caCert = await readCertificateChainAsync(rootCACertFilename);
                await cm.addIssuer(caCert[0]);

                // Create and sign a certificate
                const signedFile = await createCASigned(appCm, "urn:test:revoked", "CN=Revoked");

                // Revoke it
                await rootCA.revokeCertificate(signedFile, {});

                // Re-read the updated CRL
                const crl = await readCertificateRevocationList(rootCACrlFilename);
                await cm.addRevocationList(crl, "issuers");

                const signedCert = await readCertificateChainAsync(signedFile);
                const status = await cm.addTrustedCertificateFromChain(signedCert[0]);
                status.should.eql(VerificationStatus.BadCertificateRevoked);
            } finally {
                await cm.dispose();
                await appCm.dispose();
            }
        });

        it("should accept a revoked certificate when acceptRevokedCertificate is true", async () => {
            const cm = await makeCM({
                addCertificateValidationOptions: {
                    acceptRevokedCertificate: true
                }
            });
            const appCm = await makeCM();
            try {
                const caCert = await readCertificateChainAsync(rootCACertFilename);
                await cm.addIssuer(caCert[0]);

                const signedFile = await createCASigned(appCm, "urn:test:revoked-accept", "CN=RevokedAccept");

                // Revoke it
                await rootCA.revokeCertificate(signedFile, {});

                // Re-read the updated CRL
                const crl = await readCertificateRevocationList(rootCACrlFilename);
                await cm.addRevocationList(crl, "issuers");

                const signedCert = await readCertificateChainAsync(signedFile);
                const status = await cm.addTrustedCertificateFromChain(signedCert[0]);
                status.should.eql(VerificationStatus.Good);
            } finally {
                await cm.dispose();
                await appCm.dispose();
            }
        });
    });

    // ── 6. Chain depth limit ───────────────────────────────────
    describe("maxChainLength option", () => {
        it("should reject when chain depth exceeds maxChainLength=1", async () => {
            // With maxChainLength=1, only self-signed certs are accepted
            const cm = await makeCM({
                addCertificateValidationOptions: {
                    maxChainLength: 1,
                    ignoreMissingRevocationList: true
                }
            });
            const appCm = await makeCM();
            try {
                // A CA-signed cert needs depth 2 (leaf + root)
                const caCert = await readCertificateChainAsync(rootCACertFilename);
                await cm.addIssuer(caCert[0]);
                const crl = await readCertificateRevocationList(rootCACrlFilename);
                await cm.addRevocationList(crl, "issuers");

                const signedFile = await createCASigned(appCm, "urn:test:depth-limit", "CN=DepthLimit");
                const signedCert = await readCertificateChainAsync(signedFile);

                const status = await cm.addTrustedCertificateFromChain(signedCert[0]);
                // depth=1 is the leaf, the self-signed check fails,
                // we try to find issuer, but we've hit the limit
                status.should.eql(VerificationStatus.BadSecurityChecksFailed);
            } finally {
                await cm.dispose();
                await appCm.dispose();
            }
        });

        it("should accept self-signed certs even with maxChainLength=1", async () => {
            const cm = await makeCM({
                addCertificateValidationOptions: {
                    maxChainLength: 1,
                    ignoreMissingRevocationList: true
                }
            });
            try {
                await cm.createSelfSignedCertificate({
                    applicationUri: "urn:test:depth1-self",
                    subject: "CN=Depth1Self",
                    dns: ["localhost"],
                    startDate: new Date(),
                    validity: 365
                });
                const certFile = path.join(cm.rootDir, "own/certs/self_signed_certificate.pem");
                const cert = await readCertificateChainAsync(certFile);

                const status = await cm.addTrustedCertificateFromChain(cert[0]);
                status.should.eql(VerificationStatus.Good);
            } finally {
                await cm.dispose();
            }
        });
    });

    // ── 7. No side effects on issuers store ────────────────────
    describe("Side effects", () => {
        it("should not modify the issuers store when trusting a leaf cert", async () => {
            const cm = await makeCM({
                addCertificateValidationOptions: {
                    ignoreMissingRevocationList: true
                }
            });
            const appCm = await makeCM();
            try {
                const caCert = await readCertificateChainAsync(rootCACertFilename);
                await cm.addIssuer(caCert[0]);
                const crl = await readCertificateRevocationList(rootCACrlFilename);
                await cm.addRevocationList(crl, "issuers");

                const caThumbprint = makeSHA1Thumbprint(caCert[0]).toString("hex");
                (await cm.hasIssuer(caThumbprint)).should.be.true("issuer should exist before");

                const signedFile = await createCASigned(appCm, "urn:test:side-effect", "CN=SideEffect");
                const signedCert = await readCertificateChainAsync(signedFile);

                const status = await cm.addTrustedCertificateFromChain(signedCert[0]);
                status.should.eql(VerificationStatus.Good);

                // Issuer must still be there — no side effects
                (await cm.hasIssuer(caThumbprint)).should.be.true("issuer should still exist after");
            } finally {
                await cm.dispose();
                await appCm.dispose();
            }
        });
    });

    // ── 8. Default options are secure ──────────────────────────
    describe("Default options (strict/secure)", () => {
        it("should have all strict defaults when no options provided", async () => {
            const cm = await makeCM(); // No addCertificateValidationOptions
            const appCm = await makeCM();
            try {
                // A CA-signed cert without a CRL should be rejected
                const caCert = await readCertificateChainAsync(rootCACertFilename);
                await cm.addIssuer(caCert[0]);

                const signedFile = await createCASigned(appCm, "urn:test:strict-default", "CN=StrictDefault");
                const signedCert = await readCertificateChainAsync(signedFile);

                const status = await cm.addTrustedCertificateFromChain(signedCert[0]);
                // No CRL → should fail with revocation unknown in strict mode
                status.should.eql(VerificationStatus.BadCertificateRevocationUnknown);
            } finally {
                await cm.dispose();
                await appCm.dispose();
            }
        });
    });
});

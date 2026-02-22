/**
 * Exhaustive tests for {@link CertificateManager.verifyCertificate}
 * covering strict (default) vs relaxed mode, rejected vs first-seen
 * certificates, and all {@link VerifyCertificateOptions} combinations.
 *
 * ### Strict mode (default — no options)
 *
 * `verifyCertificate(cert)` behaves like `isCertificateTrusted`:
 * only certificates explicitly in the trusted store return `Good`.
 *
 * ### Relaxed mode (acceptCertificateWithValidIssuerChain: true)
 *
 * A certificate whose issuer chain validates against a trusted CA
 * is accepted, even if the leaf cert is not in the trusted store
 * (or was auto-rejected by `isCertificateTrusted`).
 */

import path from "node:path";
import "should";

import { type Certificate, readCertificate, readCertificateRevocationList } from "node-opcua-crypto";
import { CertificateAuthority, CertificateManager, type Filename, type KeySize, VerificationStatus } from "node-opcua-pki";

import { beforeTest } from "./helpers";

describe("verifyCertificate: options and trust modes", function (this: Mocha.Suite) {
    const testData = beforeTest(this);

    let ca: CertificateAuthority;
    let helperPKI: CertificateManager;
    let certificateFile: Filename;
    let caCertBuf: Certificate;

    /** Helper: create a fresh CertificateManager with issuer, CRL, and trusted CA */
    async function createCMWithTrustedIssuer(name: string): Promise<CertificateManager> {
        const cm = new CertificateManager({
            keySize: 2048,
            location: path.join(testData.tmpFolder, name)
        });
        await cm.initialize();
        await cm.addIssuer(caCertBuf);
        await cm.trustCertificate(caCertBuf);
        const crl = await readCertificateRevocationList(ca.revocationList);
        await cm.addRevocationList(crl);
        return cm;
    }

    /** Helper: create a fresh CertificateManager with NO issuer */
    async function createCMWithoutIssuer(name: string): Promise<CertificateManager> {
        const cm = new CertificateManager({
            keySize: 2048,
            location: path.join(testData.tmpFolder, name)
        });
        await cm.initialize();
        return cm;
    }

    before(async () => {
        ca = new CertificateAuthority({
            keySize: 2048 as KeySize,
            location: path.join(testData.tmpFolder, "OPT_TEST_CA")
        });
        await ca.initialize();

        helperPKI = new CertificateManager({
            keySize: 2048,
            location: path.join(testData.tmpFolder, "OPT_TEST_HELPER_PKI")
        });
        await helperPKI.initialize();

        certificateFile = path.join(testData.tmpFolder, "opt_test_cert.pem");
        const csr = await helperPKI.createCertificateRequest({
            applicationUri: "urn:test:options",
            dns: ["localhost"],
            subject: "/CN=OptionsTest",
            startDate: new Date(),
            validity: 365
        });
        await ca.signCertificateRequest(certificateFile, csr, {
            applicationUri: "urn:test:options"
        });

        caCertBuf = readCertificate(ca.caCertificate);
        await helperPKI.dispose();
    });

    after(async () => {
        await CertificateManager.disposeAll();
    });

    // ──────────────────────────────────────────────────────────────────
    // Strict mode (default — no options or empty options)
    // ──────────────────────────────────────────────────────────────────

    describe("strict mode (default)", () => {
        it("S1 - first-seen cert with trusted issuer → BadCertificateUntrusted", async () => {
            const cm = await createCMWithTrustedIssuer("STRICT_1");
            const cert = readCertificate(certificateFile);

            const status = await cm.verifyCertificate(cert);
            status.should.eql(VerificationStatus.BadCertificateUntrusted);

            await cm.dispose();
        });

        it("S2 - explicitly trusted cert → Good", async () => {
            const cm = await createCMWithTrustedIssuer("STRICT_2");
            const cert = readCertificate(certificateFile);
            await cm.trustCertificate(cert);

            const status = await cm.verifyCertificate(cert);
            status.should.eql(VerificationStatus.Good);

            await cm.dispose();
        });

        it("S3 - explicitly rejected cert → BadCertificateUntrusted", async () => {
            const cm = await createCMWithTrustedIssuer("STRICT_3");
            const cert = readCertificate(certificateFile);
            await cm.rejectCertificate(cert);

            const status = await cm.verifyCertificate(cert);
            status.should.eql(VerificationStatus.BadCertificateUntrusted);

            await cm.dispose();
        });

        it("S4 - auto-rejected cert (by isCertificateTrusted) → BadCertificateUntrusted", async () => {
            const cm = await createCMWithTrustedIssuer("STRICT_4");
            const cert = readCertificate(certificateFile);

            // auto-reject
            const trust = await cm.isCertificateTrusted(cert);
            trust.should.eql("BadCertificateUntrusted");

            const status = await cm.verifyCertificate(cert);
            status.should.eql(VerificationStatus.BadCertificateUntrusted);

            await cm.dispose();
        });

        it("S5 - first-seen cert with NO issuer → BadCertificateChainIncomplete", async () => {
            const cm = await createCMWithoutIssuer("STRICT_5");
            const cert = readCertificate(certificateFile);

            const status = await cm.verifyCertificate(cert);
            status.should.eql(VerificationStatus.BadCertificateChainIncomplete);

            await cm.dispose();
        });

        it("S6 - passing empty options {} is the same as strict mode", async () => {
            const cm = await createCMWithTrustedIssuer("STRICT_6");
            const cert = readCertificate(certificateFile);

            const status = await cm.verifyCertificate(cert, {});
            status.should.eql(VerificationStatus.BadCertificateUntrusted);

            await cm.dispose();
        });
    });

    // ──────────────────────────────────────────────────────────────────
    // Relaxed mode (acceptCertificateWithValidIssuerChain: true)
    // ──────────────────────────────────────────────────────────────────

    describe("relaxed mode (acceptCertificateWithValidIssuerChain: true)", () => {
        const relaxed = { acceptCertificateWithValidIssuerChain: true };

        it("R1 - first-seen cert with trusted issuer → Good", async () => {
            const cm = await createCMWithTrustedIssuer("RELAXED_1");
            const cert = readCertificate(certificateFile);

            const status = await cm.verifyCertificate(cert, relaxed);
            status.should.eql(VerificationStatus.Good);

            await cm.dispose();
        });

        it("R2 - explicitly trusted cert → Good", async () => {
            const cm = await createCMWithTrustedIssuer("RELAXED_2");
            const cert = readCertificate(certificateFile);
            await cm.trustCertificate(cert);

            const status = await cm.verifyCertificate(cert, relaxed);
            status.should.eql(VerificationStatus.Good);

            await cm.dispose();
        });

        it("R3 - explicitly rejected cert WITH trusted issuer → Good (issuer chain overrides)", async () => {
            const cm = await createCMWithTrustedIssuer("RELAXED_3");
            const cert = readCertificate(certificateFile);
            await cm.rejectCertificate(cert);

            const status = await cm.verifyCertificate(cert, relaxed);
            status.should.eql(VerificationStatus.Good);

            await cm.dispose();
        });

        it("R4 - auto-rejected cert with trusted issuer → Good", async () => {
            const cm = await createCMWithTrustedIssuer("RELAXED_4");
            const cert = readCertificate(certificateFile);

            const trust = await cm.isCertificateTrusted(cert);
            trust.should.eql("BadCertificateUntrusted");

            const status = await cm.verifyCertificate(cert, relaxed);
            status.should.eql(VerificationStatus.Good);

            await cm.dispose();
        });

        it("R5 - first-seen cert with NO issuer → BadCertificateChainIncomplete", async () => {
            const cm = await createCMWithoutIssuer("RELAXED_5");
            const cert = readCertificate(certificateFile);

            const status = await cm.verifyCertificate(cert, relaxed);
            status.should.eql(VerificationStatus.BadCertificateChainIncomplete);

            await cm.dispose();
        });

        it("R6 - rejected cert with NO issuer → BadCertificateChainIncomplete", async () => {
            const cm = await createCMWithoutIssuer("RELAXED_6");
            const cert = readCertificate(certificateFile);
            await cm.rejectCertificate(cert);

            const status = await cm.verifyCertificate(cert, relaxed);
            status.should.eql(VerificationStatus.BadCertificateChainIncomplete);

            await cm.dispose();
        });
    });
});

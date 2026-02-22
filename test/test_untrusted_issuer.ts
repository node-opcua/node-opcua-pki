/**
 * Tests for certificate verification when the issuer (CA certificate)
 * is NOT in the issuer store.
 *
 * These replicate the "when issuer (CA certificate) is not trusted"
 * describe block from node-opcua's OPCUACertificateManager tests,
 * adapted to the node-opcua-pki CertificateManager API:
 *
 *  - `verifyCertificate`  → full chain validation
 *  - `isCertificateTrusted` → trust-store-only check
 */

import path from "node:path";
import "should";

import { type Certificate, readCertificate, readCertificateRevocationList } from "node-opcua-crypto";
import { CertificateAuthority, CertificateManager, type Filename, type KeySize, VerificationStatus } from "node-opcua-pki";

import { beforeTest } from "./helpers";

describe("verifyCertificate: when issuer (CA) is NOT trusted", function (this: Mocha.Suite) {
    const testData = beforeTest(this);

    let ca: CertificateAuthority;
    let helperPKI: CertificateManager;
    let certificateFile: Filename;
    let caCertBuf: Certificate;

    before(async () => {
        // Create a CA and a helper PKI to generate a CA-signed certificate
        ca = new CertificateAuthority({
            keySize: 2048 as KeySize,
            location: path.join(testData.tmpFolder, "UNTRUSTED_CA")
        });
        await ca.initialize();

        helperPKI = new CertificateManager({
            keySize: 2048,
            location: path.join(testData.tmpFolder, "UNTRUSTED_HELPER_PKI")
        });
        await helperPKI.initialize();

        certificateFile = path.join(testData.tmpFolder, "untrusted_issuer_cert.pem");
        const csr = await helperPKI.createCertificateRequest({
            applicationUri: "urn:test:untrusted-issuer",
            dns: ["localhost"],
            subject: "/CN=UntrustedIssuerTest",
            startDate: new Date(),
            validity: 365
        });
        await ca.signCertificateRequest(certificateFile, csr, {
            applicationUri: "urn:test:untrusted-issuer"
        });

        caCertBuf = readCertificate(ca.caCertificate);
        await helperPKI.dispose();
    });

    after(async () => {
        await CertificateManager.disposeAll();
    });

    // ──────────────────────────────────────────────────────────────────
    // AQU01 – first-seen certificate with no issuer in store
    // ──────────────────────────────────────────────────────────────────

    it("AQU01 - should reject a first-seen CA-signed certificate when the issuer is unknown", async () => {
        const cm = new CertificateManager({
            keySize: 2048,
            location: path.join(testData.tmpFolder, "AQU01")
        });
        await cm.initialize();

        const cert = readCertificate(certificateFile);

        // isCertificateTrusted only checks the trust store
        const isTrusted = await cm.isCertificateTrusted(cert);
        isTrusted.should.eql("BadCertificateUntrusted");

        // verifyCertificate performs full chain validation →
        // chain is incomplete because the issuer is missing
        const status = await cm.verifyCertificate(cert);
        status.should.eql(VerificationStatus.BadCertificateChainIncomplete);

        await cm.dispose();
    });

    // ──────────────────────────────────────────────────────────────────
    // AQU02 – certificate explicitly trusted, but issuer still unknown
    // ──────────────────────────────────────────────────────────────────

    it("AQU02 - should reject a trusted CA-signed certificate when the issuer is not in the issuer store", async () => {
        const cm = new CertificateManager({
            keySize: 2048,
            location: path.join(testData.tmpFolder, "AQU02")
        });
        await cm.initialize();

        const cert = readCertificate(certificateFile);
        await cm.trustCertificate(cert);

        // Even though the leaf certificate is trusted, the chain
        // cannot be verified because the issuer is missing.
        const status = await cm.verifyCertificate(cert);
        status.should.eql(VerificationStatus.BadCertificateChainIncomplete);

        await cm.dispose();
    });

    // ──────────────────────────────────────────────────────────────────
    // AQU03 – certificate trusted AND issuer certificate trusted,
    //         but CRL is missing
    // ──────────────────────────────────────────────────────────────────

    it("AQU03 - should reject when issuer cert is added but CRL is missing", async () => {
        const cm = new CertificateManager({
            keySize: 2048,
            location: path.join(testData.tmpFolder, "AQU03")
        });
        await cm.initialize();

        const cert = readCertificate(certificateFile);
        await cm.trustCertificate(cert);

        // Add the issuer certificate (but do NOT add the CRL)
        await cm.addIssuer(caCertBuf);
        await cm.trustCertificate(caCertBuf);

        // Chain is now complete, but CRL is missing →
        // revocation status cannot be determined
        const status = await cm.verifyCertificate(cert);
        status.should.eql(VerificationStatus.BadCertificateRevocationUnknown);

        await cm.dispose();
    });

    // ──────────────────────────────────────────────────────────────────
    // AQU04 – everything in place: certificate trusted, issuer trusted,
    //         CRL present → Good
    // ──────────────────────────────────────────────────────────────────

    it("AQU04 - should accept when issuer cert AND CRL are both present", async () => {
        const cm = new CertificateManager({
            keySize: 2048,
            location: path.join(testData.tmpFolder, "AQU04")
        });
        await cm.initialize();

        const cert = readCertificate(certificateFile);
        await cm.trustCertificate(cert);

        // Add the CA cert and its CRL
        await cm.addIssuer(caCertBuf);
        await cm.trustCertificate(caCertBuf);

        const crl = await readCertificateRevocationList(ca.revocationList);
        await cm.addRevocationList(crl);

        const status = await cm.verifyCertificate(cert);
        status.should.eql(VerificationStatus.Good);

        await cm.dispose();
    });
});

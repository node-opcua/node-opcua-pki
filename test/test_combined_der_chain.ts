/**
 * Regression test for combined DER chain bug.
 *
 * When a certificate chain is passed as a single Buffer containing
 * multiple concatenated DER-encoded certificates (a "combined DER"),
 * `verifyCertificateAsync` must split the buffer into individual
 * certificates before calling `#innerVerifyCertificateAsync`.
 *
 * Without the fix, the combined buffer is wrapped in a one-element
 * array `[combinedBuffer]`, so `findIssuerCertificateInChain` only
 * ever sees the leaf certificate (the first DER element) and fails
 * to locate the issuer — returning `BadCertificateChainIncomplete`.
 */

import path from "node:path";
import "should";
import { type Certificate, readCertificateChain, readCertificateRevocationList, split_der } from "node-opcua-crypto";
import { CertificateAuthority, CertificateManager, type Filename, type KeySize, VerificationStatus } from "node-opcua-pki";
import { beforeTest } from "./helpers";

describe("BUG: verifyCertificate with combined DER chain", function (this: Mocha.Suite) {
    const testData = beforeTest(this);

    let ca: CertificateAuthority;
    let helperPKI: CertificateManager;
    let certificateFile: Filename;
    let caCert: Certificate;
    let leafCert: Certificate;
    let combinedDer: Buffer;

    async function createCertificateManager(folderName: string): Promise<CertificateManager> {
        const cm = new CertificateManager({
            keySize: 2048,
            location: path.join(testData.tmpFolder, folderName)
        });
        await cm.initialize();
        return cm;
    }

    before(async () => {
        // Create a CA
        ca = new CertificateAuthority({
            keySize: 2048 as KeySize,
            location: path.join(testData.tmpFolder, "COMBINED_DER_CA")
        });
        await ca.initialize();

        // Create a helper PKI to generate a CA-signed certificate
        helperPKI = await createCertificateManager("COMBINED_DER_HELPER_PKI");

        certificateFile = path.join(testData.tmpFolder, "combined_der_test_cert.pem");
        const csr = await helperPKI.createCertificateRequest({
            applicationUri: "urn:test:combined-der",
            dns: ["localhost"],
            subject: "/CN=CombinedDERTest",
            startDate: new Date(),
            validity: 365
        });
        await ca.signCertificateRequest(certificateFile, csr, {
            applicationUri: "urn:test:combined-der"
        });

        // Preload certificates into shared variables
        const caCertChain = readCertificateChain(ca.caCertificate);
        caCert = caCertChain[0];

        const leafCerts = readCertificateChain(certificateFile);
        leafCert = leafCerts[0];

        // Simulate what an OPC UA client sends over the wire (combined DER)
        combinedDer = Buffer.concat([leafCert, caCert]);

        await helperPKI.dispose();
    });

    after(async () => {
        await CertificateManager.disposeAll();
    });

    it("should find the issuer when certificate chain is a single combined DER buffer", async () => {
        const cm = await createCertificateManager("COMBINED_DER_TEST_PKI");

        // Trust the leaf certificate
        await cm.trustCertificate(leafCert);

        // Add the CA cert as an issuer and add its CRL
        await cm.addIssuer(caCert);
        const crl = await readCertificateRevocationList(ca.revocationList);
        await cm.addRevocationList(crl);

        // ── Baseline: verify with an array of separate certificates ──
        const statusWithArray = await cm.verifyCertificate([leafCert, caCert]);
        statusWithArray.should.eql(VerificationStatus.Good, "verification with Certificate[] should succeed");

        // Sanity-check: split_der should produce two certificates
        const parts = split_der(combinedDer);
        parts.length.should.eql(2, "combined DER should contain 2 certificates");

        // ── Bug scenario: verify with a combined DER buffer ──────────
        const statusWithCombinedDer = await cm.verifyCertificate(combinedDer);
        statusWithCombinedDer.should.eql(VerificationStatus.Good, "verification with combined DER buffer should succeed");

        await cm.dispose();
    });

    it("should find the issuer in combined DER even when CA is NOT in the issuer store", async () => {
        const cm = await createCertificateManager("COMBINED_DER_NO_ISSUER_PKI");

        // Trust the leaf but do NOT add the CA to the issuer store
        await cm.trustCertificate(leafCert);

        const status = await cm.verifyCertificate(combinedDer);

        // The CA cert IS found in the chain but is not in the issuer store.
        // It prevents BadCertificateChainIncomplete. Since the CA CRL is not there,
        // it may return BadCertificateRevocationUnknown or Good depending on config.
        status.should.not.eql(
            VerificationStatus.BadCertificateChainIncomplete,
            "combined DER chain should NOT be reported as incomplete"
        );

        await cm.dispose();
    });

    it("should verify successfully with combined DER chain in relaxed mode even if leaf is rejected", async () => {
        const cm = await createCertificateManager("COMBINED_DER_RELAXED_PKI");

        // Explicitly Reject the leaf certificate
        await cm.rejectCertificate(leafCert);

        // But Trust the CA (issuer) and add CRL
        await cm.addIssuer(caCert);
        await cm.trustCertificate(caCert);
        const crl = await readCertificateRevocationList(ca.revocationList);
        await cm.addRevocationList(crl);

        const relaxedOptions = { acceptCertificateWithValidIssuerChain: true };

        // Even though leaf is rejected, relaxed mode overrides it since issuer is in the trusted store.
        // And we pass the `combinedDer` chain!
        const status = await cm.verifyCertificate(combinedDer, relaxedOptions);

        status.should.eql(VerificationStatus.Good, "relaxed mode should succeed with combined DER when issuer is trusted");

        await cm.dispose();
    });

    it("should gracefully handle trailing garbage data in combined DER chain", async () => {
        const cm = await createCertificateManager("COMBINED_DER_GARBAGE_PKI");

        // Append 10 bytes of random garbage to the end of the combined DER
        const garbage = Buffer.from("invalid123");
        const corruptedDer = Buffer.concat([combinedDer, garbage]);

        // It should reject it since the final bytes don't parse as a valid cert
        const status = await cm.verifyCertificate(corruptedDer);
        status.should.eql(VerificationStatus.BadCertificateInvalid, "verification should reject trailing garbage data");

        await cm.dispose();
    });

    it("should gracefully handle an empty buffer", async () => {
        const cm = await createCertificateManager("COMBINED_DER_EMPTY_PKI");

        const status = await cm.verifyCertificate(Buffer.alloc(0));

        status.should.eql(VerificationStatus.BadCertificateInvalid, "verification should reject empty buffer");

        await cm.dispose();
    });

    it("should evaluate the CA if the combined DER order is reversed (leaf last)", async () => {
        const cm = await createCertificateManager("COMBINED_DER_REVERSE_PKI");

        // Trust the CA since it's going to end up being the evaluated target!
        await cm.addIssuer(caCert);
        await cm.trustCertificate(caCert);

        // Put the CA FIRST in the buffer. OPC UA specifications dictate the first certificate
        // is the instance certificate to evaluate. If a client sends CA followed by Leaf,
        // the PKI will evaluate the CA.
        const reversedDer = Buffer.concat([caCert, leafCert]);

        const status = await cm.verifyCertificate(reversedDer);

        // Since the CA is the first cert, and it's trusted and self-signed, it should return Good.
        // It successfully ignores the incorrectly placed trailing leaf.
        status.should.eql(VerificationStatus.Good, "verification evaluates the first element of the combined DER buffer");

        await cm.dispose();
    });
});

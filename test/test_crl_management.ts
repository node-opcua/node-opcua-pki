import fs from "node:fs";
import path from "node:path";
import "should";

import { readCertificate } from "node-opcua-crypto";
import { CertificateManager, type CertificateManagerOptions } from "../lib";
import { beforeTest } from "./helpers";

describe("CRL Management - addRevocationList target and clearRevocationLists", function () {
    const testData = beforeTest(this);

    let certificateManager: CertificateManager;

    const caCertificateFilename = path.join(__dirname, "fixtures/CTT_sample_certificates/CA/certs/ctt_ca1I.der");
    const crlFilename = path.join(__dirname, "fixtures/CTT_sample_certificates/CA/crl/ctt_ca1I.crl");

    beforeEach(async () => {
        const location = path.join(testData.tmpFolder, `CRL_test_${Date.now()}`);
        const options: CertificateManagerOptions = { location };
        certificateManager = new CertificateManager(options);
        await certificateManager.initialize();

        // Add issuer CA certificate so CRL verification works
        const caCert = readCertificate(caCertificateFilename);
        await certificateManager.addIssuer(caCert, false);
    });

    afterEach(async () => {
        await certificateManager.dispose();
    });

    it("addRevocationList with default target should write to issuers/crl", async () => {
        const crl = fs.readFileSync(crlFilename);
        const status = await certificateManager.addRevocationList(crl);
        status.should.eql("Good");

        // Verify file exists in issuers/crl
        const issuersCrlFiles = fs.readdirSync(certificateManager.issuersCrlFolder);
        const crlFiles = issuersCrlFiles.filter((f) => f.startsWith("crl_"));
        crlFiles.length.should.be.greaterThan(0, "CRL file should exist in issuers/crl");

        // Verify trusted/crl is empty
        const trustedCrlFiles = fs.readdirSync(certificateManager.crlFolder);
        const trustedCrlOnly = trustedCrlFiles.filter((f) => f.startsWith("crl_"));
        trustedCrlOnly.length.should.eql(0, "trusted/crl should be empty");
    });

    it("addRevocationList with target 'issuers' should write to issuers/crl", async () => {
        const crl = fs.readFileSync(crlFilename);
        const status = await certificateManager.addRevocationList(crl, "issuers");
        status.should.eql("Good");

        const issuersCrlFiles = fs.readdirSync(certificateManager.issuersCrlFolder);
        const crlFiles = issuersCrlFiles.filter((f) => f.startsWith("crl_"));
        crlFiles.length.should.be.greaterThan(0, "CRL file should exist in issuers/crl");
    });

    it("addRevocationList with target 'trusted' should write to trusted/crl", async () => {
        const crl = fs.readFileSync(crlFilename);
        const status = await certificateManager.addRevocationList(crl, "trusted");
        status.should.eql("Good");

        // Verify file exists in trusted/crl
        const trustedCrlFiles = fs.readdirSync(certificateManager.crlFolder);
        const crlFiles = trustedCrlFiles.filter((f) => f.startsWith("crl_"));
        crlFiles.length.should.be.greaterThan(0, "CRL file should exist in trusted/crl");

        // Verify issuers/crl is empty
        const issuersCrlFiles = fs.readdirSync(certificateManager.issuersCrlFolder);
        const issuerCrlOnly = issuersCrlFiles.filter((f) => f.startsWith("crl_"));
        issuerCrlOnly.length.should.eql(0, "issuers/crl should be empty");
    });

    it("clearRevocationLists('issuers') should clear only issuers/crl", async () => {
        const crl = fs.readFileSync(crlFilename);

        // Add CRLs to both folders
        await certificateManager.addRevocationList(crl, "issuers");
        await certificateManager.addRevocationList(crl, "trusted");

        // Verify both folders have files
        const issuersBefore = fs.readdirSync(certificateManager.issuersCrlFolder).filter((f) => f.startsWith("crl_"));
        const trustedBefore = fs.readdirSync(certificateManager.crlFolder).filter((f) => f.startsWith("crl_"));
        issuersBefore.length.should.be.greaterThan(0);
        trustedBefore.length.should.be.greaterThan(0);

        // Clear only issuers
        await certificateManager.clearRevocationLists("issuers");

        // issuers/crl should be empty
        const issuersAfter = fs.readdirSync(certificateManager.issuersCrlFolder).filter((f) => f.startsWith("crl_"));
        issuersAfter.length.should.eql(0, "issuers/crl should be empty after clear");

        // trusted/crl should still have files
        const trustedAfter = fs.readdirSync(certificateManager.crlFolder).filter((f) => f.startsWith("crl_"));
        trustedAfter.length.should.be.greaterThan(0, "trusted/crl should still have files");
    });

    it("clearRevocationLists('trusted') should clear only trusted/crl", async () => {
        const crl = fs.readFileSync(crlFilename);

        await certificateManager.addRevocationList(crl, "issuers");
        await certificateManager.addRevocationList(crl, "trusted");

        await certificateManager.clearRevocationLists("trusted");

        // trusted/crl should be empty
        const trustedAfter = fs.readdirSync(certificateManager.crlFolder).filter((f) => f.startsWith("crl_"));
        trustedAfter.length.should.eql(0, "trusted/crl should be empty after clear");

        // issuers/crl should still have files
        const issuersAfter = fs.readdirSync(certificateManager.issuersCrlFolder).filter((f) => f.startsWith("crl_"));
        issuersAfter.length.should.be.greaterThan(0, "issuers/crl should still have files");
    });

    it("clearRevocationLists('all') should clear both folders", async () => {
        const crl = fs.readFileSync(crlFilename);

        await certificateManager.addRevocationList(crl, "issuers");
        await certificateManager.addRevocationList(crl, "trusted");

        await certificateManager.clearRevocationLists("all");

        const issuersAfter = fs.readdirSync(certificateManager.issuersCrlFolder).filter((f) => f.startsWith("crl_"));
        const trustedAfter = fs.readdirSync(certificateManager.crlFolder).filter((f) => f.startsWith("crl_"));

        issuersAfter.length.should.eql(0, "issuers/crl should be empty");
        trustedAfter.length.should.eql(0, "trusted/crl should be empty");
    });

    it("clearRevocationLists should not fail on empty folders", async () => {
        // Both folders should be empty already
        await certificateManager.clearRevocationLists("all");
        // No error should be thrown
    });
});

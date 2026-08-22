import fs from "node:fs";
import path from "node:path";
import "should";

import {
    certificateMatchesPrivateKey,
    convertPEMtoDER,
    exploreCertificate,
    identifyDERContent,
    makeSHA1Thumbprint,
    readCertificateChainAsync,
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
import { execute_openssl, passinArg, passoutArg } from "node-opcua-pki-priv/toolbox/with_openssl";
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

        describe("with a passphrase-encrypted private key (CertificateManager privateKeyPassphrase)", () => {
            const keyPassphrase = "key passphrase with $hell `chars`";
            let encCertFile: string;
            let encKeyFile: string;

            before(async () => {
                const cm = new CertificateManager({
                    location: path.join(testData.tmpFolder, "PFX_CM_ENC"),
                    privateKeyPassphrase: keyPassphrase
                });
                await cm.initialize();
                await cm.createSelfSignedCertificate({
                    applicationUri: "urn:test:pfx:enc",
                    subject: "CN=PFXTestEnc",
                    dns: ["localhost"],
                    startDate: new Date(),
                    validity: 365
                });
                encCertFile = path.join(cm.rootDir, "own/certs/self_signed_certificate.pem");
                encKeyFile = cm.privateKey;
                await cm.dispose();
                fs.readFileSync(encKeyFile, "utf-8").should.match(/ENCRYPTED PRIVATE KEY/);
            });

            it("should create a PFX when given the key passphrase", async () => {
                const out = path.join(testData.tmpFolder, "test_enc_key.pfx");
                await createPFX({
                    certificateFile: encCertFile,
                    privateKeyFile: encKeyFile,
                    privateKeyPassphrase: keyPassphrase,
                    outputFile: out,
                    passphrase: "bundle pass"
                });
                identifyDERContent(fs.readFileSync(out)).should.eql("PKCS12");
                const pem = await extractPrivateKeyFromPFX({ pfxFile: out, passphrase: "bundle pass" });
                pem.should.match(/PRIVATE KEY/);
            });

            it("should fail fast (not hang) when the key passphrase is missing", async function () {
                this.timeout(20000);
                const out = path.join(testData.tmpFolder, "test_enc_key_nopass.pfx");
                let threw = false;
                try {
                    await createPFX({ certificateFile: encCertFile, privateKeyFile: encKeyFile, outputFile: out });
                } catch {
                    threw = true;
                }
                threw.should.eql(true, "createPFX must reject, not wait for a passphrase prompt");
                fs.existsSync(out).should.eql(false);
            });
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
            const originalCert = await readCertificateChainAsync(certFile);
            const originalThumbprint = makeSHA1Thumbprint(originalCert[0]).toString("hex");
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
            const chain = await readCertificateChainAsync(certFile);
            const originalInfo = exploreCertificate(chain[0]);

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
            const originalCaCert = await readCertificateChainAsync(caCertFile);
            const originalCaThumbprint = makeSHA1Thumbprint(originalCaCert[0]).toString("hex");
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
            const originalCert = await readCertificateChainAsync(certFile);
            const originalInfo = exploreCertificate(originalCert[0]);
            const originalThumbprint = makeSHA1Thumbprint(originalCert[0]).toString("hex");

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

    // ── passphrases containing shell metacharacters ─────────────
    //
    // Regression coverage for the fix that stopped passphrases from being
    // interpolated into the openssl command string (previously
    // `-passin/-passout pass:${passphrase}`, executed via a shell). A
    // passphrase containing shell metacharacters must round-trip like any
    // other passphrase, not break the command or, worse, execute part of
    // itself as a shell command.
    describe("passphrases containing shell metacharacters", () => {
        // one passphrase covering several classically dangerous shell
        // metacharacters: command substitution, backticks, quotes, pipe,
        // semicolon, redirection, backslash, dollar-sign expansion.
        const nastyPassphrase = "p$(id)`touch /tmp/pwned`;|&<>!\"'\\pass";

        it("should create and extract a PFX round-trip with a shell-metacharacter passphrase", async () => {
            const nastyPfxFile = path.join(testData.tmpFolder, "test_nasty_passphrase.pfx");

            await createPFX({
                certificateFile: certFile,
                privateKeyFile: keyFile,
                outputFile: nastyPfxFile,
                passphrase: nastyPassphrase
            });

            fs.existsSync(nastyPfxFile).should.be.true("PFX file should exist");

            const extractedPem = await extractCertificateFromPFX({
                pfxFile: nastyPfxFile,
                passphrase: nastyPassphrase
            });
            const extractedDer = convertPEMtoDER(extractedPem);
            const originalCert = await readCertificateChainAsync(certFile);
            makeSHA1Thumbprint(extractedDer)
                .toString("hex")
                .should.eql(makeSHA1Thumbprint(originalCert[0]).toString("hex"), "thumbprints must match");

            // proof the injection attempt never ran as a shell command
            fs.existsSync("/tmp/pwned").should.be.false("passphrase content must never be interpreted by a shell");
        });

        it("should fail (not inject) when extracting with the wrong shell-metacharacter passphrase", async () => {
            const nastyPfxFile = path.join(testData.tmpFolder, "test_nasty_passphrase_2.pfx");

            await createPFX({
                certificateFile: certFile,
                privateKeyFile: keyFile,
                outputFile: nastyPfxFile,
                passphrase: nastyPassphrase
            });

            let threw = false;
            try {
                await extractCertificateFromPFX({
                    pfxFile: nastyPfxFile,
                    passphrase: `${nastyPassphrase}-wrong`
                });
            } catch {
                threw = true;
            }
            threw.should.be.true("should throw when the shell-metacharacter passphrase is wrong, not execute part of it");
            fs.existsSync("/tmp/pwned").should.be.false("passphrase content must never be interpreted by a shell");
        });
    });

    // ── openssl interoperability ───────────────────────────────
    //
    // These helpers no longer spawn `openssl pkcs12`, so "openssl and this
    // package agree on the format" stopped being true by construction and
    // became a claim that has to be checked. Both directions matter: users
    // hold bundles openssl wrote, and hand bundles to tools that expect
    // openssl to be able to read them.
    describe("openssl interoperability", () => {
        it("reads a bundle that openssl created", async () => {
            const opensslPfx = path.join(testData.tmpFolder, "made_by_openssl.pfx");
            const passout = passoutArg("openssl made me");
            await execute_openssl(["pkcs12", "-export", "-in", certFile, "-inkey", keyFile, "-out", opensslPfx, ...passout.args], {
                env: passout.env
            });

            const result = await extractAllFromPFX({ pfxFile: opensslPfx, passphrase: "openssl made me" });
            const originalCert = await readCertificateChainAsync(certFile);
            makeSHA1Thumbprint(convertPEMtoDER(result.certificate))
                .toString("hex")
                .should.eql(makeSHA1Thumbprint(originalCert[0]).toString("hex"));
            certificateMatchesPrivateKey(convertPEMtoDER(result.certificate), readPrivateKey(keyFile)).should.be.true();
        });

        it("writes a bundle that openssl can read", async () => {
            const nativePfx = path.join(testData.tmpFolder, "made_by_us.pfx");
            await createPFX({
                certificateFile: certFile,
                privateKeyFile: keyFile,
                outputFile: nativePfx,
                passphrase: "we made it",
                caCertificateFiles: [caCertFile]
            });

            const passin = passinArg("we made it");
            const dumped = await execute_openssl(["pkcs12", "-in", nativePfx, "-nokeys", "-clcerts", "-nodes", ...passin.args], {
                env: passin.env
            });
            const opensslView = convertPEMtoDER(dumped);
            const originalCert = await readCertificateChainAsync(certFile);
            makeSHA1Thumbprint(opensslView)
                .toString("hex")
                .should.eql(makeSHA1Thumbprint(originalCert[0]).toString("hex"), "openssl must see the same identity we wrote");
        });

        it("explains, rather than leaks an OID, when asked to read an openssl 1.x RC2 bundle", async function () {
            // openssl 1.x encrypted the certificate safe with 40-bit RC2 by
            // default. That cipher is broken; openssl 3 will not produce or
            // read it without -legacy, and this package will not read it at
            // all. What it must do is say so in terms someone can act on.
            const legacyPfx = path.join(testData.tmpFolder, "legacy_rc2.pfx");
            const passout = passoutArg("legacy");
            try {
                await execute_openssl(
                    ["pkcs12", "-export", "-legacy", "-in", certFile, "-inkey", keyFile, "-out", legacyPfx, ...passout.args],
                    { env: passout.env, hideErrorMessage: true }
                );
            } catch {
                // no legacy provider in this openssl build, so the bundle
                // this test is about cannot be produced here
                return this.skip();
            }

            let message = "";
            try {
                await extractCertificateFromPFX({ pfxFile: legacyPfx, passphrase: "legacy" });
            } catch (err) {
                message = (err as Error).message;
            }
            message.should.match(/not supported/, "the failure must be reported, not swallowed");
            message.should.match(/-legacy/, "the message must name the flag that converts the file");
            message.should.match(/openssl pkcs12 -export/, "the message must show the conversion command");
        });
    });

    // ── properties the openssl implementation could not offer ──

    describe("bundle contents", () => {
        it("round-trips a friendly name", async () => {
            const named = path.join(testData.tmpFolder, "named.pfx");
            await createPFX({
                certificateFile: certFile,
                privateKeyFile: keyFile,
                outputFile: named,
                friendlyName: "my application identity"
            });

            (await extractAllFromPFX({ pfxFile: named })).friendlyName?.should.eql("my application identity");
            (await dumpPFX(named)).should.containEql("my application identity");
        });

        it("treats extra PEM blocks in the certificate file as the issuer chain", async () => {
            // a leaf+chain PEM is how most tools hand over an identity, and
            // the CA certificate must end up in the chain rather than being
            // dropped or mistaken for the identity
            const combined = path.join(testData.tmpFolder, "leaf_and_chain.pem");
            fs.writeFileSync(combined, `${fs.readFileSync(certFile, "utf-8")}\n${fs.readFileSync(caCertFile, "utf-8")}`);

            const out = path.join(testData.tmpFolder, "from_chain_pem.pfx");
            await createPFX({ certificateFile: combined, privateKeyFile: keyFile, outputFile: out });

            const result = await extractAllFromPFX({ pfxFile: out });
            const leaf = await readCertificateChainAsync(certFile);
            makeSHA1Thumbprint(convertPEMtoDER(result.certificate))
                .toString("hex")
                .should.eql(makeSHA1Thumbprint(leaf[0]).toString("hex"), "the first block is the identity");
            const ca = await readCertificateChainAsync(caCertFile);
            makeSHA1Thumbprint(convertPEMtoDER(result.caCertificates))
                .toString("hex")
                .should.eql(makeSHA1Thumbprint(ca[0]).toString("hex"), "the rest are the chain");
        });

        it("refuses a key that does not belong to the certificate", async () => {
            // `openssl pkcs12 -export` fails with "No certificate matches
            // private key"; without this guard the native path would write a
            // well-formed bundle that no consumer can use.
            const out = path.join(testData.tmpFolder, "mismatched.pfx");
            let message = "";
            try {
                await createPFX({ certificateFile: caCertFile, privateKeyFile: keyFile, outputFile: out });
            } catch (err) {
                message = (err as Error).message;
            }
            message.should.match(/does not match/);
            fs.existsSync(out).should.eql(false, "a bundle that cannot be used must not be written");
        });

        it("states in the dump that the enclosed key matches the certificate", async () => {
            // the question a bundle that will not load is usually being asked
            (await dumpPFX(pfxFile)).should.containEql("matches this certificate");
        });
    });
});

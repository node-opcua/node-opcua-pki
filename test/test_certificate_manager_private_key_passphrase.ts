import fs from "node:fs";
import path from "node:path";
import "should";
import { coercePrivateKeyPem, type PrivateKey, readPrivateKey } from "node-opcua-crypto";
import { CertificateManager, PrivateKeyPassphraseRequiredError } from "node-opcua-pki";
import { beforeTest } from "./helpers";

describe("CertificateManager private key passphrase", function (this: Mocha.Suite) {
    this.timeout(40000);

    const testData = beforeTest(this);

    it("should write an ENCRYPTED PRIVATE KEY PEM when a passphrase is configured", async () => {
        const location = path.join(testData.tmpFolder, "PKI_pass_fresh");
        const cm = new CertificateManager({ location, privateKeyPassphrase: "correct horse battery staple" });
        await cm.initialize();

        const pem = fs.readFileSync(cm.privateKey, "utf-8");
        pem.should.match(/-----BEGIN ENCRYPTED PRIVATE KEY-----/);

        await cm.dispose();
    });

    it("should self-sign a certificate and create a CSR through a passphrase-protected key", async () => {
        const location = path.join(testData.tmpFolder, "PKI_pass_ops");
        const passphrase = "correct horse battery staple";
        const cm = new CertificateManager({ location, privateKeyPassphrase: passphrase });
        await cm.initialize();

        await cm.createSelfSignedCertificate({
            applicationUri: "urn:test:passphrase",
            subject: "CN=PassphraseTest",
            dns: ["localhost"],
            startDate: new Date(),
            validity: 365
        });
        fs.existsSync(path.join(location, "own/certs/self_signed_certificate.pem")).should.eql(true);

        const csrFile = await cm.createCertificateRequest({
            applicationUri: "urn:test:passphrase",
            subject: "CN=PassphraseTest",
            dns: ["localhost"]
        });
        fs.existsSync(csrFile).should.eql(true);

        await cm.dispose();
    });

    it("initialize() should fail closed when the on-disk key is encrypted but no passphrase is configured", async () => {
        const location = path.join(testData.tmpFolder, "PKI_pass_missing");
        const passphrase = "correct horse battery staple";

        const cm1 = new CertificateManager({ location, privateKeyPassphrase: passphrase });
        await cm1.initialize();
        await cm1.dispose();

        const cm2 = new CertificateManager({ location });
        let threw: Error | undefined;
        try {
            await cm2.initialize();
        } catch (err) {
            threw = err as Error;
        }
        (threw instanceof PrivateKeyPassphraseRequiredError).should.eql(true);
    });

    it("initialize() should fail closed with the wrong passphrase", async () => {
        const location = path.join(testData.tmpFolder, "PKI_pass_wrong");
        const cm1 = new CertificateManager({ location, privateKeyPassphrase: "right passphrase" });
        await cm1.initialize();
        await cm1.dispose();

        const cm2 = new CertificateManager({ location, privateKeyPassphrase: "wrong passphrase" });
        let threw = false;
        try {
            await cm2.initialize();
        } catch {
            threw = true;
        }
        threw.should.eql(true);
    });

    it("getPrivateKey() should support a passphrase supplied via a function, called lazily and at most once", async () => {
        const location = path.join(testData.tmpFolder, "PKI_pass_fn");
        let calls = 0;
        const cm = new CertificateManager({
            location,
            privateKeyPassphrase: async () => {
                calls++;
                return "function-supplied passphrase";
            }
        });
        calls.should.eql(0, "the passphrase function must not be called before it's needed");

        await cm.initialize();
        calls.should.eql(1, "the passphrase function must have been called exactly once by initialize()");

        // subsequent operations reuse the cached key: no further calls
        await cm.createSelfSignedCertificate({
            applicationUri: "urn:test:passphrase:fn",
            subject: "CN=PassphraseFn",
            dns: ["localhost"],
            startDate: new Date(),
            validity: 365
        });
        await cm.createCertificateRequest({
            applicationUri: "urn:test:passphrase:fn",
            subject: "CN=PassphraseFn",
            dns: ["localhost"]
        });
        await cm.getPrivateKey();
        calls.should.eql(1, "the passphrase function must not be called again once the key is cached");

        await cm.dispose();

        // a fresh instance on the same (now encrypted) install: exactly one call again
        let calls2 = 0;
        const cm2 = new CertificateManager({
            location,
            privateKeyPassphrase: async () => {
                calls2++;
                return "function-supplied passphrase";
            }
        });
        await cm2.initialize();
        await cm2.getPrivateKey();
        calls2.should.eql(1);
        await cm2.dispose();
    });

    it("initialize() should encrypt an existing plaintext key in place when a passphrase is configured", async () => {
        const location = path.join(testData.tmpFolder, "PKI_pass_migrate");
        const cm1 = new CertificateManager({ location });
        await cm1.initialize();
        const plaintextPem = fs.readFileSync(cm1.privateKey, "utf-8");
        plaintextPem.should.not.match(/ENCRYPTED/);
        const before: PrivateKey = readPrivateKey(cm1.privateKey);
        await cm1.dispose();

        const cm2 = new CertificateManager({ location, privateKeyPassphrase: "now protected" });
        await cm2.initialize();
        const pem = fs.readFileSync(cm2.privateKey, "utf-8");
        pem.should.match(/-----BEGIN ENCRYPTED PRIVATE KEY-----/);
        // same key material, no stray temp/plaintext copy left next to it
        const after: PrivateKey = readPrivateKey(cm2.privateKey, "now protected");
        coercePrivateKeyPem(after).should.eql(coercePrivateKeyPem(before));
        fs.readdirSync(path.dirname(cm2.privateKey)).should.eql(["private_key.pem"]);
        await cm2.dispose();

        // and a passphrase-less instance now fails closed, proving the migration stuck
        const cm3 = new CertificateManager({ location });
        let threw: unknown;
        try {
            await cm3.initialize();
        } catch (err) {
            threw = err;
        }
        (threw instanceof PrivateKeyPassphraseRequiredError).should.eql(true);
    });

    it("a failed initialize() must leave the instance re-initializable, not stuck", async () => {
        const location = path.join(testData.tmpFolder, "PKI_pass_retry");
        const cm1 = new CertificateManager({ location, privateKeyPassphrase: "right" });
        await cm1.initialize();
        await cm1.dispose();

        let attempts = 0;
        const cm2 = new CertificateManager({
            location,
            privateKeyPassphrase: async () => (++attempts === 1 ? "wrong" : "right")
        });
        let threw = false;
        try {
            await cm2.initialize();
        } catch {
            threw = true;
        }
        threw.should.eql(true, "first attempt with the wrong passphrase must throw");

        // second attempt: the resolver now returns the right passphrase and
        // initialize() must actually run again (not early-return on a stuck state)
        await cm2.initialize();
        attempts.should.eql(2);
        const key = await cm2.getPrivateKey();
        key.should.be.ok();
        await cm2.dispose();
    });

    describe("reencryptPrivateKey", () => {
        it("should round-trip none -> passphrase -> none", async () => {
            const location = path.join(testData.tmpFolder, "PKI_pass_roundtrip");
            const cm = new CertificateManager({ location });
            await cm.initialize();

            let pem = fs.readFileSync(cm.privateKey, "utf-8");
            pem.should.not.match(/ENCRYPTED/);

            await cm.reencryptPrivateKey(undefined, "new passphrase");
            pem = fs.readFileSync(cm.privateKey, "utf-8");
            pem.should.match(/-----BEGIN ENCRYPTED PRIVATE KEY-----/);

            // verify it actually decrypts with the new passphrase
            const decrypted: PrivateKey = readPrivateKey(cm.privateKey, "new passphrase");
            decrypted.hidden.should.be.ok();

            await cm.reencryptPrivateKey("new passphrase", undefined);
            pem = fs.readFileSync(cm.privateKey, "utf-8");
            pem.should.not.match(/ENCRYPTED/);
            // no temp file left behind by either rotation
            fs.readdirSync(path.dirname(cm.privateKey)).should.eql(["private_key.pem"]);

            await cm.dispose();
        });

        it("should refuse to reencrypt when a privateKeyProvider is configured", async () => {
            const location = path.join(testData.tmpFolder, "PKI_pass_provider_reencrypt");
            const cm = new CertificateManager({
                location,
                privateKeyProvider: {
                    async getPrivateKey(): Promise<PrivateKey> {
                        throw new Error("should not be called in this test");
                    }
                }
            });
            let threw = false;
            try {
                await cm.reencryptPrivateKey(undefined, "x");
            } catch {
                threw = true;
            }
            threw.should.eql(true);
        });
    });

    describe("privateKeyProvider", () => {
        it("should bypass disk entirely for getPrivateKey() and certificate operations", async () => {
            const location = path.join(testData.tmpFolder, "PKI_pass_provider");

            // Build a real, valid PrivateKey from a throwaway CertificateManager,
            // then serve it via a stub provider on a *different* location that
            // never gets its own on-disk key.
            const keySource = new CertificateManager({ location: path.join(testData.tmpFolder, "PKI_pass_provider_source") });
            await keySource.initialize();
            const providedKey: PrivateKey = readPrivateKey(keySource.privateKey);
            await keySource.dispose();

            let getPrivateKeyCalls = 0;
            const cm = new CertificateManager({
                location,
                privateKeyProvider: {
                    async getPrivateKey(): Promise<PrivateKey> {
                        getPrivateKeyCalls++;
                        return providedKey;
                    }
                }
            });
            await cm.initialize();

            getPrivateKeyCalls.should.be.greaterThan(0);
            fs.existsSync(cm.privateKey).should.eql(
                false,
                "no key file should ever be written to disk when a provider is configured"
            );

            await cm.createSelfSignedCertificate({
                applicationUri: "urn:test:provider",
                subject: "CN=ProviderTest",
                dns: ["localhost"],
                startDate: new Date(),
                validity: 365
            });
            fs.existsSync(path.join(location, "own/certs/self_signed_certificate.pem")).should.eql(true);
            fs.existsSync(cm.privateKey).should.eql(false, "self-signed cert creation must not have written a key file either");

            await cm.dispose();
        });
    });
});

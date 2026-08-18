import fs from "node:fs";
import path from "node:path";
import "should";
import { coercePrivateKeyPem, exploreCertificate, readCertificate, readPrivateKey } from "node-opcua-crypto";
import { CertificateAuthority, CertificateManager, PrivateKeyPassphraseRequiredError } from "node-opcua-pki";
import { beforeTest } from "./helpers";

describe("CertificateAuthority private key passphrase", function (this: Mocha.Suite) {
    this.timeout(120000);
    const testData = beforeTest(this);

    const passphrase = "ca passphrase with $hell `chars`";

    async function makeLeafCsr(location: string): Promise<{ cm: CertificateManager; csr: string }> {
        const cm = new CertificateManager({ location });
        await cm.initialize();
        const csr = await cm.createCertificateRequest({
            applicationUri: "urn:test:ca-pass",
            subject: "CN=Leaf",
            dns: ["localhost"]
        });
        return { cm, csr };
    }

    it("should write an encrypted cakey.pem and still sign, revoke, and regenerate the CRL", async () => {
        const location = path.join(testData.tmpFolder, "CA_pass_ops");
        let calls = 0;
        const ca = new CertificateAuthority({
            keySize: 2048,
            location,
            subject: "/CN=PassCA",
            privateKeyPassphrase: async () => {
                calls++;
                return passphrase;
            }
        });
        await ca.initialize();
        fs.readFileSync(ca.privateKey, "utf-8").should.match(/-----BEGIN ENCRYPTED PRIVATE KEY-----/);
        fs.existsSync(ca.caCertificate).should.eql(true);
        fs.existsSync(ca.revocationList).should.eql(true, "initial CRL must have been generated");

        const { cm, csr } = await makeLeafCsr(path.join(testData.tmpFolder, "PKI_ca_pass_leaf"));
        const cert = path.join(cm.rootDir, "own/certs/signed.pem");
        await ca.signCertificateRequest(cert, csr, { applicationUri: "urn:test:ca-pass", startDate: new Date(), validity: 30 });
        fs.existsSync(cert).should.eql(true);
        exploreCertificate(readCertificate(cert)).tbsCertificate.issuer.commonName?.should.eql("PassCA");

        const crlBefore = fs.statSync(ca.revocationList).mtimeMs;
        await ca.revokeCertificate(cert, { reason: "keyCompromise" });
        fs.readFileSync(path.join(location, "index.txt"), "utf-8").should.match(/^R\t/m, "index.txt must record the revocation");
        fs.statSync(ca.revocationList).mtimeMs.should.be.aboveOrEqual(crlBefore);

        const result = await ca.generateKeyPairAndSignDER({
            applicationUri: "urn:test:ca-pass:kp",
            subject: "CN=KP",
            validity: 30
        });
        result.certificateDer.length.should.be.greaterThan(0);

        calls.should.eql(1, "the passphrase function must be resolved once per CA instance");
        await cm.dispose();
    });

    it("initialize() should fail closed with a missing or wrong passphrase on an encrypted CA key", async () => {
        const location = path.join(testData.tmpFolder, "CA_pass_missing");
        const ca1 = new CertificateAuthority({ keySize: 2048, location, subject: "/CN=PassCA", privateKeyPassphrase: passphrase });
        await ca1.initialize();

        let threw: unknown;
        try {
            await new CertificateAuthority({ keySize: 2048, location, subject: "/CN=PassCA" }).initialize();
        } catch (err) {
            threw = err;
        }
        (threw instanceof PrivateKeyPassphraseRequiredError).should.eql(true, "missing passphrase");

        let threwWrong = false;
        try {
            await new CertificateAuthority({
                keySize: 2048,
                location,
                subject: "/CN=PassCA",
                privateKeyPassphrase: "wrong"
            }).initialize();
        } catch {
            threwWrong = true;
        }
        threwWrong.should.eql(true, "wrong passphrase");
        // and the on-disk key is untouched by the failed attempts
        fs.readFileSync(ca1.privateKey, "utf-8").should.match(/ENCRYPTED PRIVATE KEY/);
    });

    it("initialize() should encrypt an existing plaintext CA key in place when a passphrase is configured", async () => {
        const location = path.join(testData.tmpFolder, "CA_pass_migrate");
        const ca1 = new CertificateAuthority({ keySize: 2048, location, subject: "/CN=MigrateCA" });
        await ca1.initialize();
        fs.readFileSync(ca1.privateKey, "utf-8").should.not.match(/ENCRYPTED/);
        const before = coercePrivateKeyPem(readPrivateKey(ca1.privateKey));

        const ca2 = new CertificateAuthority({
            keySize: 2048,
            location,
            subject: "/CN=MigrateCA",
            privateKeyPassphrase: passphrase
        });
        await ca2.initialize();
        fs.readFileSync(ca2.privateKey, "utf-8").should.match(/-----BEGIN ENCRYPTED PRIVATE KEY-----/);
        coercePrivateKeyPem(await ca2.getPrivateKey()).should.eql(before);
        fs.readdirSync(path.dirname(ca2.privateKey))
            .filter((f) => f.endsWith(".tmp"))
            .should.eql([]);

        // the migrated CA can still sign
        const { cm, csr } = await makeLeafCsr(path.join(testData.tmpFolder, "PKI_ca_migrate_leaf"));
        const cert = path.join(cm.rootDir, "own/certs/signed.pem");
        await ca2.signCertificateRequest(cert, csr, { applicationUri: "urn:test:ca-pass", startDate: new Date(), validity: 30 });
        fs.existsSync(cert).should.eql(true);
        await cm.dispose();
    });

    it("a subordinate CA is signed with the issuer's passphrase and signs with its own", async () => {
        const rootLoc = path.join(testData.tmpFolder, "CA_pass_root");
        const subLoc = path.join(testData.tmpFolder, "CA_pass_sub");
        const root = new CertificateAuthority({
            keySize: 2048,
            location: rootLoc,
            subject: "/CN=Root",
            privateKeyPassphrase: "root pass"
        });
        await root.initialize();
        const sub = new CertificateAuthority({
            keySize: 2048,
            location: subLoc,
            subject: "/CN=Sub",
            issuerCA: root,
            privateKeyPassphrase: "sub pass"
        });
        await sub.initialize();
        exploreCertificate(readCertificate(sub.caCertificate)).tbsCertificate.issuer.commonName?.should.eql("Root");
        fs.readFileSync(sub.privateKey, "utf-8").should.match(/ENCRYPTED PRIVATE KEY/);

        const { cm, csr } = await makeLeafCsr(path.join(testData.tmpFolder, "PKI_ca_sub_leaf"));
        const cert = path.join(cm.rootDir, "own/certs/signed.pem");
        await sub.signCertificateRequest(cert, csr, { applicationUri: "urn:test:ca-pass", startDate: new Date(), validity: 30 });
        exploreCertificate(readCertificate(cert)).tbsCertificate.issuer.commonName?.should.eql("Sub");
        await cm.dispose();
    });

    it("initializeCSR + external signing + installCACertificate work with an encrypted key", async () => {
        const rootLoc = path.join(testData.tmpFolder, "CA_pass_ext_root");
        const subLoc = path.join(testData.tmpFolder, "CA_pass_ext_sub");
        const root = new CertificateAuthority({
            keySize: 2048,
            location: rootLoc,
            subject: "/CN=ExtRoot",
            privateKeyPassphrase: "root pass"
        });
        await root.initialize();

        const sub = new CertificateAuthority({
            keySize: 2048,
            location: subLoc,
            subject: "/CN=ExtSub",
            privateKeyPassphrase: "sub pass"
        });
        const r1 = await sub.initializeCSR();
        r1.status.should.eql("created");
        fs.readFileSync(sub.privateKey, "utf-8").should.match(/ENCRYPTED PRIVATE KEY/);

        // restart before install: still pending, key still readable
        const subAgain = new CertificateAuthority({
            keySize: 2048,
            location: subLoc,
            subject: "/CN=ExtSub",
            privateKeyPassphrase: "sub pass"
        });
        (await subAgain.initializeCSR()).status.should.eql("pending");

        const signed = path.join(testData.tmpFolder, "ext_sub_signed.pem");
        await root.signCACertificateRequest(signed, (r1 as { csrPath: string }).csrPath, { validity: 3650 });
        const install = await subAgain.installCACertificate(signed);
        install.status.should.eql("success");
        fs.existsSync(subAgain.revocationList).should.eql(true);
        (await subAgain.initializeCSR()).status.should.eql("ready");
    });

    it("reencryptPrivateKey should round-trip none -> passphrase -> none and leave no temp file", async () => {
        const location = path.join(testData.tmpFolder, "CA_pass_reencrypt");
        const ca = new CertificateAuthority({ keySize: 2048, location, subject: "/CN=ReencCA" });
        await ca.initialize();
        await ca.reencryptPrivateKey(undefined, "p1");
        fs.readFileSync(ca.privateKey, "utf-8").should.match(/ENCRYPTED/);
        readPrivateKey(ca.privateKey, "p1").hidden.should.be.ok();
        await ca.reencryptPrivateKey("p1", undefined);
        fs.readFileSync(ca.privateKey, "utf-8").should.not.match(/ENCRYPTED/);
        fs.readdirSync(path.dirname(ca.privateKey))
            .filter((f) => f.endsWith(".tmp"))
            .should.eql([]);
    });
});

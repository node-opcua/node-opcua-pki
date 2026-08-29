import nodeCrypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import "should";
import { type IKeyOperations, keyOperationsFromPrivateKey, x509 } from "node-opcua-crypto";
import { CertificateManager, PrivateKeyUnavailableError } from "node-opcua-pki";
import { beforeTest } from "./helpers";

/**
 * A KMS-style provider for the tests: async-only, no sync fast path, backed
 * by an in-memory key so results stay verifiable. Counts metadata probes so
 * the fail-closed initialize() behavior is observable.
 */
function makeMockOpaqueOps(): { ops: IKeyOperations; metadataProbes: () => number } {
    const { privateKey } = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const local = keyOperationsFromPrivateKey({ hidden: privateKey.export({ type: "pkcs8", format: "pem" }).toString() });
    let probes = 0;
    const ops: IKeyOperations = {
        sign: (data, params) => local.sign(data, params),
        decryptBlock: (block, params) => local.decryptBlock(block, params),
        getKeyMetadata: async () => {
            probes += 1;
            return local.getKeyMetadata();
        },
        getPublicKey: () => local.getPublicKey()
    };
    return { ops, metadataProbes: () => probes };
}

describe("CertificateManager keyOperations (opaque private key)", function (this: Mocha.Suite) {
    this.timeout(40000);

    const testData = beforeTest(this);

    it("rejects keyOperations combined with privateKeyProvider or privateKeyPassphrase", () => {
        const location = path.join(testData.tmpFolder, "PKI_ops_combo");
        const { ops } = makeMockOpaqueOps();
        (() =>
            new CertificateManager({
                location,
                keyOperations: ops,
                privateKeyProvider: { getPrivateKey: async () => ({ hidden: "" }) }
            })).should.throw(/mutually exclusive/);
        (() => new CertificateManager({ location, keyOperations: ops, privateKeyPassphrase: "secret" })).should.throw(
            /meaningless with 'keyOperations'/
        );
    });

    it("initialize() probes the provider, generates no on-disk key, and getPrivateKey() throws", async () => {
        const location = path.join(testData.tmpFolder, "PKI_ops_opaque");
        const { ops, metadataProbes } = makeMockOpaqueOps();
        const cm = new CertificateManager({ location, keyOperations: ops });
        cm.isPrivateKeyOpaque().should.eql(true);

        await cm.initialize();
        metadataProbes().should.be.greaterThan(0);
        fs.existsSync(cm.privateKey).should.eql(false, "no private_key.pem may be generated for an opaque key");

        await cm.getPrivateKey().should.be.rejectedWith(PrivateKeyUnavailableError);
        await cm.reencryptPrivateKey(undefined, "new pass").should.be.rejectedWith(PrivateKeyUnavailableError);

        cm.getKeyOperations().should.equal(ops);
        await cm.dispose();
    });

    it("initialize() fails closed when the opaque provider is broken", async () => {
        const location = path.join(testData.tmpFolder, "PKI_ops_broken");
        const broken: IKeyOperations = {
            sign: async () => {
                throw new Error("HSM unreachable");
            },
            decryptBlock: async () => {
                throw new Error("HSM unreachable");
            },
            getKeyMetadata: async () => {
                throw new Error("HSM unreachable");
            }
        };
        const cm = new CertificateManager({ location, keyOperations: broken });
        await cm.initialize().should.be.rejectedWith(/HSM unreachable/);
        await cm.dispose();
    });

    it("getKeyOperations() over a local key: stable object, correct metadata, verifiable signature", async () => {
        const location = path.join(testData.tmpFolder, "PKI_ops_local");
        const cm = new CertificateManager({ location });
        await cm.initialize();
        cm.isPrivateKeyOpaque().should.eql(false);

        const ops = cm.getKeyOperations();
        cm.getKeyOperations().should.equal(ops, "the lazy wrap must be a stable object");

        const metadata = await ops.getKeyMetadata();
        metadata.keyType.should.eql("RSA");
        metadata.modulusLength.should.eql(cm.keySize / 8);

        // a signature made through the wrap verifies against the wrap's own public key
        const data = Buffer.from("payload to sign");
        const signature = await ops.sign(data, { padding: "RSA-PKCS1-v1_5", hash: "SHA-256" });
        if (!ops.getPublicKey) {
            throw new Error("the lazy wrap must expose getPublicKey");
        }
        const publicKey = nodeCrypto.createPublicKey({
            key: Buffer.from(await ops.getPublicKey()),
            format: "der",
            type: "spki"
        });
        nodeCrypto.createVerify("RSA-SHA256").update(data).verify(publicKey, signature).should.eql(true);

        await cm.dispose();
    });

    it("getKeyOperations() decrypts what the key's public half encrypted (local key)", async () => {
        const location = path.join(testData.tmpFolder, "PKI_ops_decrypt");
        const cm = new CertificateManager({ location });
        await cm.initialize();

        const ops = cm.getKeyOperations();
        if (!ops.getPublicKey) {
            throw new Error("the lazy wrap must expose getPublicKey");
        }
        const publicKey = nodeCrypto.createPublicKey({
            key: Buffer.from(await ops.getPublicKey()),
            format: "der",
            type: "spki"
        });
        const plain = Buffer.from("secret payload");
        const block = nodeCrypto.publicEncrypt(
            { key: publicKey, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
            plain
        );
        const decrypted = await ops.decryptBlock(block, { padding: "RSA-OAEP", oaepHash: "SHA-256" });
        decrypted.equals(plain).should.eql(true);

        await cm.dispose();
    });

    it("keyOperations-related exports are available from node-opcua-pki itself", () => {
        PrivateKeyUnavailableError.should.be.a.Function();
        new PrivateKeyUnavailableError().name.should.eql("PrivateKeyUnavailableError");
    });

    it("createCertificateRequest works over an opaque key: the CSR verifies and carries the provider's public key", async () => {
        const location = path.join(testData.tmpFolder, "PKI_ops_csr");
        const { ops } = makeMockOpaqueOps();
        const cm = new CertificateManager({ location, keyOperations: ops });
        await cm.initialize();

        const csrFile = await cm.createCertificateRequest({
            applicationUri: "urn:test:opaque-renewal",
            subject: "CN=OpaqueRenewal",
            dns: ["localhost"]
        });
        fs.existsSync(csrFile).should.eql(true);

        const csrPem = await fs.promises.readFile(csrFile, "utf-8");
        const request = new x509.Pkcs10CertificateRequest(csrPem);
        (await request.verify()).should.eql(true, "the proof-of-possession signature must verify");
        if (!ops.getPublicKey) {
            throw new Error("test setup: ops must expose getPublicKey");
        }
        Buffer.from(request.publicKey.rawData)
            .equals(Buffer.from(await ops.getPublicKey()))
            .should.eql(true, "the CSR must embed the provider's public key");

        await cm.dispose();
    });

    it("createCertificateRequest names the missing capability when the provider lacks getPublicKey", async () => {
        const location = path.join(testData.tmpFolder, "PKI_ops_csr_nopub");
        const { ops } = makeMockOpaqueOps();
        delete ops.getPublicKey;
        const cm = new CertificateManager({ location, keyOperations: ops });
        await cm.initialize();

        await cm
            .createCertificateRequest({ applicationUri: "urn:test:nopub", subject: "CN=NoPub", dns: [] })
            .should.be.rejectedWith(/getPublicKey/);

        await cm.dispose();
    });

    it("createSelfSignedCertificate over an opaque key states the node-opcua-crypto floor until 5.11.0 is in", async () => {
        // TEMPORARY companion of the toolbox guard: becomes a positive test
        // when node-opcua-crypto >= 5.11.0 (node-opcua/node-opcua-crypto#89) is bumped in
        const location = path.join(testData.tmpFolder, "PKI_ops_selfsigned");
        const { ops } = makeMockOpaqueOps();
        const cm = new CertificateManager({ location, keyOperations: ops });
        await cm.initialize();

        await cm
            .createSelfSignedCertificate({
                applicationUri: "urn:test:opaque-selfsigned",
                subject: "CN=OpaqueSelfSigned",
                dns: ["localhost"],
                startDate: new Date(),
                validity: 365
            })
            .should.be.rejectedWith(/node-opcua-crypto >= 5\.11\.0/);

        await cm.dispose();
    });
});

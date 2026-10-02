/**
 * {@link CertificateManager.verifyCertificate} on a two-level chain:
 * which CA has to be in the trusted store.
 *
 * OPC 10000-4 6.1.3 builds the chain from the trusted and the issuer
 * certificates together, then applies the Trust List Check: the
 * certificate is untrusted only when it is not trusted itself and
 * "none of the CA Certificates in the chain is trusted". A trusted
 * root with a merely known intermediate must therefore be enough.
 */

import { createPrivateKey, webcrypto } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { convertPEMtoDER, readCertificate, x509 } from "node-opcua-crypto";
import { CertificateAuthority, CertificateManager, type KeySize, VerificationStatus } from "node-opcua-pki";
import should from "should";

import { beforeTest } from "./helpers";

type Store = "trusted" | "issuers";

describe("verifyCertificate: trust through a two-level chain", function (this: Mocha.Suite) {
    const testData = beforeTest(this);

    let root: CertificateAuthority;
    let issuing: CertificateAuthority;
    let leaf: Buffer;
    const managers: CertificateManager[] = [];

    async function storeWith(name: string, rootStore: Store, issuingStore: Store, crls = true): Promise<CertificateManager> {
        const cm = new CertificateManager({ keySize: 2048, location: path.join(testData.tmpFolder, name) });
        await cm.initialize();
        managers.push(cm);
        for (const [ca, where] of [
            [root, rootStore],
            [issuing, issuingStore]
        ] as const) {
            const der = ca.getCACertificateDER();
            if (where === "trusted") {
                await cm.trustCertificate(der);
            } else {
                await cm.addIssuer(der);
            }
            if (crls) await cm.addRevocationList(ca.getCRLDER(), where);
        }
        return cm;
    }

    before(async () => {
        root = new CertificateAuthority({
            keySize: 2048 as KeySize,
            location: path.join(testData.tmpFolder, "CHAIN_ROOT_CA"),
            subject: "/CN=Chain Trust Root CA"
        });
        await root.initialize();
        issuing = new CertificateAuthority({
            keySize: 2048 as KeySize,
            location: path.join(testData.tmpFolder, "CHAIN_ISSUING_CA"),
            subject: "/CN=Chain Trust Issuing CA",
            issuerCA: root
        });
        await issuing.initialize();
        leaf = (
            await issuing.generateKeyPairAndSignDER({
                applicationUri: "urn:test:chain-trust:leaf",
                subject: "/CN=Chain Trust Leaf",
                dns: ["localhost"]
            })
        ).certificateDer;
    });

    after(async () => {
        for (const cm of managers) await cm.dispose();
    });

    const relaxed = { acceptCertificateWithValidIssuerChain: true };

    it("accepts the leaf when both CAs are trusted", async () => {
        const cm = await storeWith("chain_both_trusted", "trusted", "trusted");
        should(await cm.verifyCertificate(leaf, relaxed)).eql(VerificationStatus.Good);
    });

    it("accepts the leaf when the issuing CA is trusted and the root is only known", async () => {
        const cm = await storeWith("chain_issuing_trusted", "issuers", "trusted");
        should(await cm.verifyCertificate(leaf, relaxed)).eql(VerificationStatus.Good);
    });

    it("accepts the leaf when the root is trusted and the issuing CA is only known", async () => {
        const cm = await storeWith("chain_root_trusted", "trusted", "issuers");
        should(await cm.verifyCertificate(leaf, relaxed)).eql(VerificationStatus.Good);
    });

    it("refuses the leaf when no CA of the chain is trusted", async () => {
        const cm = await storeWith("chain_none_trusted", "issuers", "issuers");
        should(await cm.verifyCertificate(leaf, relaxed)).eql(VerificationStatus.BadCertificateUntrusted);
    });

    it("stays strict by default: a trusted root does not make an unknown leaf trusted", async () => {
        const cm = await storeWith("chain_root_trusted_strict", "trusted", "issuers");
        should(await cm.verifyCertificate(leaf)).eql(VerificationStatus.BadCertificateUntrusted);
    });

    it("still needs the CRL of the known issuing CA's issuer", async () => {
        const cm = await storeWith("chain_root_trusted_no_crl", "trusted", "issuers", false);
        should(await cm.verifyCertificate(leaf, relaxed)).not.eql(VerificationStatus.Good);
    });

    it("refuses the leaf when the known issuing CA has been revoked by the trusted root", async () => {
        // its own root: a revocation here must not touch the CRL the other cases use
        const ownRoot = new CertificateAuthority({
            keySize: 2048 as KeySize,
            location: path.join(testData.tmpFolder, "CHAIN_REVOKING_ROOT_CA"),
            subject: "/CN=Chain Trust Revoking Root CA"
        });
        await ownRoot.initialize();
        const revokedIssuing = new CertificateAuthority({
            keySize: 2048 as KeySize,
            location: path.join(testData.tmpFolder, "CHAIN_REVOKED_ISSUING_CA"),
            subject: "/CN=Chain Trust Revoked Issuing CA",
            issuerCA: ownRoot
        });
        await revokedIssuing.initialize();
        const revokedLeaf = (
            await revokedIssuing.generateKeyPairAndSignDER({
                applicationUri: "urn:test:chain-trust:revoked",
                subject: "/CN=Chain Trust Leaf Of Revoked CA",
                dns: ["localhost"]
            })
        ).certificateDer;
        const cm = new CertificateManager({ keySize: 2048, location: path.join(testData.tmpFolder, "chain_revoked_issuing") });
        await cm.initialize();
        managers.push(cm);
        await cm.trustCertificate(ownRoot.getCACertificateDER());
        await cm.addRevocationList(ownRoot.getCRLDER(), "trusted");
        await cm.addIssuer(revokedIssuing.getCACertificateDER());
        await cm.addRevocationList(revokedIssuing.getCRLDER(), "issuers");

        // control: accepted until the root revokes the issuing CA
        should(await cm.verifyCertificate(revokedLeaf, relaxed)).eql(VerificationStatus.Good);

        await ownRoot.revokeCertificate(revokedIssuing.caCertificate, {});
        await cm.clearRevocationLists("trusted");
        await cm.addRevocationList(ownRoot.getCRLDER(), "trusted");

        should(await cm.verifyCertificate(revokedLeaf, relaxed)).eql(VerificationStatus.BadSecurityChecksFailed);
    });

    /**
     * A certificate signed with the key of an END-ENTITY certificate that
     * the trusted CA issued. The end-entity certificate is not a CA
     * (no basicConstraints cA), so nothing it signs may be accepted,
     * however valid its own chain is.
     */
    async function forgedBelowEndEntity(name: string): Promise<{ forged: Buffer; endEntity: Buffer }> {
        const holder = new CertificateManager({ keySize: 2048, location: path.join(testData.tmpFolder, `${name}_holder`) });
        await holder.initialize();
        managers.push(holder);
        const csr = await holder.createCertificateRequest({
            applicationUri: `urn:test:chain-trust:${name}`,
            dns: ["localhost"],
            subject: `/CN=Chain Trust End Entity ${name}`,
            startDate: new Date(),
            validity: 365
        });
        const endEntityFile = path.join(testData.tmpFolder, `${name}_end_entity.pem`);
        await issuing.signCertificateRequest(endEntityFile, csr, {
            applicationUri: `urn:test:chain-trust:${name}`,
            startDate: new Date(),
            validity: 365
        });
        const endEntity = readCertificate(endEntityFile);

        const algorithm = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
        const pkcs8 = createPrivateKey(fs.readFileSync(holder.privateKey, "utf-8")).export({ type: "pkcs8", format: "der" });
        const endEntityKey = await webcrypto.subtle.importKey("pkcs8", pkcs8, algorithm, false, ["sign"]);
        const forgedKeys = await webcrypto.subtle.generateKey(
            { ...algorithm, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
            true,
            ["sign", "verify"]
        );
        const endEntityX509 = new x509.X509Certificate(endEntity);
        const forged = await x509.X509CertificateGenerator.create(
            {
                serialNumber: "0A0B0C",
                subject: "CN=Chain Trust Forged",
                issuer: endEntityX509.subject,
                notBefore: new Date(Date.now() - 60_000),
                notAfter: new Date(Date.now() + 86_400_000),
                signingAlgorithm: algorithm,
                publicKey: forgedKeys.publicKey,
                signingKey: endEntityKey,
                extensions: [
                    await x509.SubjectKeyIdentifierExtension.create(forgedKeys.publicKey, false, webcrypto as Crypto),
                    await x509.AuthorityKeyIdentifierExtension.create(endEntityX509, false, webcrypto as Crypto)
                ]
            },
            webcrypto as Crypto
        );
        return { forged: Buffer.from(forged.rawData), endEntity: convertPEMtoDER(fs.readFileSync(endEntityFile, "utf-8")) };
    }

    it("refuses a certificate signed by an end-entity certificate of a trusted CA, presented with it as a chain", async () => {
        const { forged, endEntity } = await forgedBelowEndEntity("forged_chain");
        const cm = await storeWith("chain_forged_presented", "trusted", "trusted");
        // control: the end-entity certificate itself is fine
        should(await cm.verifyCertificate(endEntity, relaxed)).eql(VerificationStatus.Good);
        should(await cm.verifyCertificate([forged, endEntity], relaxed)).not.eql(VerificationStatus.Good);
        // the end-entity certificate has no CRL of its own: that must not be what refuses the forgery
        const lenient = { ...relaxed, ignoreMissingRevocationList: true };
        should(await cm.verifyCertificate([forged, endEntity], lenient)).eql(VerificationStatus.BadCertificateUntrusted);
    });

    it("refuses it as well when the end-entity certificate sits in the issuers store", async () => {
        const { forged, endEntity } = await forgedBelowEndEntity("forged_store");
        const cm = await storeWith("chain_forged_in_store", "trusted", "trusted");
        await cm.addIssuer(endEntity);
        should(await cm.verifyCertificate(forged, relaxed)).not.eql(VerificationStatus.Good);

        // a fresh store: the first verification above has filed what it saw
        const cm2 = await storeWith("chain_forged_in_store_lenient", "trusted", "trusted");
        await cm2.addIssuer(endEntity);
        should(await cm2.verifyCertificate(forged, { ...relaxed, ignoreMissingRevocationList: true })).eql(
            VerificationStatus.BadCertificateUntrusted
        );
    });

    // ── crafted chains: basicConstraints decide what may pass trust on ──

    const algorithm = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
    type Keys = Awaited<ReturnType<typeof newKeys>>;
    function newKeys() {
        return webcrypto.subtle.generateKey(
            { ...algorithm, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
            true,
            ["sign", "verify"]
        );
    }
    let serial = 0x100;
    async function craft(
        subject: string,
        keys: Keys,
        issuer: { name: string; keys: Keys } | undefined,
        basicConstraints: { ca: boolean; pathLength?: number } | undefined
    ): Promise<Buffer> {
        const extensions: x509.Extension[] = [
            await x509.SubjectKeyIdentifierExtension.create(keys.publicKey, false, webcrypto as Crypto),
            await x509.AuthorityKeyIdentifierExtension.create((issuer?.keys ?? keys).publicKey, false, webcrypto as Crypto)
        ];
        if (basicConstraints) {
            extensions.push(new x509.BasicConstraintsExtension(basicConstraints.ca, basicConstraints.pathLength, true));
            if (basicConstraints.ca) {
                extensions.push(new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true));
            }
        }
        const certificate = await x509.X509CertificateGenerator.create(
            {
                serialNumber: (serial++).toString(16),
                subject: `CN=${subject}`,
                issuer: `CN=${issuer?.name ?? subject}`,
                notBefore: new Date(Date.now() - 60_000),
                notAfter: new Date(Date.now() + 86_400_000),
                signingAlgorithm: algorithm,
                publicKey: keys.publicKey,
                signingKey: (issuer?.keys ?? keys).privateKey,
                extensions
            },
            webcrypto as Crypto
        );
        return Buffer.from(certificate.rawData);
    }
    async function emptyStore(name: string): Promise<CertificateManager> {
        const cm = new CertificateManager({ keySize: 2048, location: path.join(testData.tmpFolder, name) });
        await cm.initialize();
        managers.push(cm);
        return cm;
    }
    // crafted CAs publish no CRL: revocation is not what these cases are about
    const lenient = { ...relaxed, ignoreMissingRevocationList: true };

    it("honours pathLenConstraint: a root that allows no CA below it does not pass trust through one", async () => {
        const [rootKeys, caKeys, leafKeys] = await Promise.all([newKeys(), newKeys(), newKeys()]);

        for (const [pathLength, expected] of [
            [undefined, VerificationStatus.Good],
            [1, VerificationStatus.Good],
            [0, VerificationStatus.BadCertificateUntrusted]
        ] as const) {
            const name = `Crafted Root pathLen ${pathLength}`;
            const rootCertificate = await craft(name, rootKeys, undefined, { ca: true, pathLength });
            const caCertificate = await craft("Crafted Sub CA", caKeys, { name, keys: rootKeys }, { ca: true });
            const leafCertificate = await craft("Crafted Leaf", leafKeys, { name: "Crafted Sub CA", keys: caKeys }, { ca: false });

            const cm = await emptyStore(`chain_pathlen_${pathLength}`);
            await cm.trustCertificate(rootCertificate);
            await cm.addIssuer(caCertificate);
            should(await cm.verifyCertificate(leafCertificate, lenient)).eql(expected);
        }
    });

    it("does not pass trust through a trusted certificate that is not a CA", async () => {
        const [peerKeys, caKeys, leafKeys] = await Promise.all([newKeys(), newKeys(), newKeys()]);
        // an ordinary peer the operator trusted, whose key then signs a "CA"
        const peer = await craft("Crafted Trusted Peer", peerKeys, undefined, { ca: false });
        const rogueCa = await craft("Crafted Rogue CA", caKeys, { name: "Crafted Trusted Peer", keys: peerKeys }, { ca: true });
        const leafCertificate = await craft(
            "Crafted Rogue Leaf",
            leafKeys,
            { name: "Crafted Rogue CA", keys: caKeys },
            { ca: false }
        );

        const cm = await emptyStore("chain_trusted_non_ca");
        await cm.trustCertificate(peer);
        should(await cm.verifyCertificate([leafCertificate, rogueCa], lenient)).eql(VerificationStatus.BadCertificateUntrusted);
    });
});

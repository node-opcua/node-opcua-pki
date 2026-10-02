/**
 * Two behaviours of {@link CertificateManager.verifyCertificate} on a
 * two-level chain:
 *
 * - revocation is looked up in the CRLs of the certificate's own issuer,
 *   in both stores, and in no other CA's CRL;
 * - an outdated issuer the caller accepts
 *   (`acceptOutDatedIssuerCertificate`) does not fail the verification.
 */

import { webcrypto } from "node:crypto";
import path from "node:path";
import { exploreCertificate, exploreCertificateRevocationList, x509 } from "node-opcua-crypto";
import { CertificateAuthority, CertificateManager, type KeySize, VerificationStatus } from "node-opcua-pki";
import should from "should";

import { beforeTest } from "./helpers";

describe("verifyCertificate: revocation lookup and outdated issuers", function (this: Mocha.Suite) {
    const testData = beforeTest(this);
    const managers: CertificateManager[] = [];
    const relaxed = { acceptCertificateWithValidIssuerChain: true };

    async function emptyStore(name: string): Promise<CertificateManager> {
        const cm = new CertificateManager({ keySize: 2048, location: path.join(testData.tmpFolder, name) });
        await cm.initialize();
        managers.push(cm);
        return cm;
    }

    after(async () => {
        for (const cm of managers) await cm.dispose();
    });

    describe("revocation lookup", () => {
        let root: CertificateAuthority;
        let issuing: CertificateAuthority;

        const newCA = async (name: string, issuerCA?: CertificateAuthority) => {
            const ca = new CertificateAuthority({
                keySize: 2048 as KeySize,
                location: path.join(testData.tmpFolder, name),
                subject: `/CN=${name}`,
                ...(issuerCA ? { issuerCA } : {})
            });
            await ca.initialize();
            return ca;
        };
        const newLeaf = async (name: string) =>
            (
                await issuing.generateKeyPairAndSignDER({
                    applicationUri: `urn:test:revocation-lookup:${name}`,
                    subject: `/CN=Revocation Lookup ${name}`,
                    dns: ["localhost"]
                })
            ).certificateDer;
        const serialOf = (der: Buffer) => exploreCertificate(der).tbsCertificate.serialNumber;
        const revokedSerialsOf = (ca: CertificateAuthority) =>
            exploreCertificateRevocationList(ca.getCRLDER()).tbsCertList.revokedCertificates.map((r) => r.userCertificate);

        before(async () => {
            root = await newCA("REVLOOKUP_ROOT_CA");
            issuing = await newCA("REVLOOKUP_ISSUING_CA", root);
        });

        it("does not read a serial number in the CRL of the CA above the issuer", async () => {
            // The root revokes other CAs it issued: their serial numbers land in the ROOT's CRL.
            for (const name of ["REVLOOKUP_WITHDRAWN_CA_1", "REVLOOKUP_WITHDRAWN_CA_2", "REVLOOKUP_WITHDRAWN_CA_3"]) {
                const withdrawn = await newCA(name, root);
                await root.revokeCertificate(withdrawn.caCertificate, {});
            }
            const revokedByRoot = revokedSerialsOf(root);
            revokedByRoot.length.should.be.greaterThan(0);

            // The issuing CA numbers its certificates on its own: one of its
            // leaves soon carries a serial the root revoked.
            let leaf: Buffer | undefined;
            for (let i = 0; i < 12 && !leaf; i++) {
                const candidate = await newLeaf(`collision-${i}`);
                if (revokedByRoot.includes(serialOf(candidate))) leaf = candidate;
            }
            should.exist(leaf, "no leaf of the issuing CA shares a serial number with a certificate the root revoked");
            should(revokedSerialsOf(issuing)).not.containEql(serialOf(leaf as Buffer));

            const cm = await emptyStore("revlookup_collision");
            await cm.trustCertificate(root.getCACertificateDER());
            await cm.addRevocationList(root.getCRLDER(), "trusted");
            await cm.trustCertificate(issuing.getCACertificateDER());
            await cm.addRevocationList(issuing.getCRLDER(), "trusted");

            should(await cm.isCertificateRevoked(leaf as Buffer)).eql(VerificationStatus.Good);
            should(await cm.verifyCertificate(leaf as Buffer, relaxed)).eql(VerificationStatus.Good);
        });

        it("sees a revocation listed in the trusted store when the issuers store holds an older CRL", async () => {
            const leaf = await newLeaf("stale-crl");
            const before = issuing.getCRLDER();
            await issuing.revokeCertificateDER(leaf);
            const after = issuing.getCRLDER();
            should(after.equals(before)).eql(false);

            const cm = await emptyStore("revlookup_two_editions");
            await cm.trustCertificate(root.getCACertificateDER());
            await cm.addRevocationList(root.getCRLDER(), "trusted");
            await cm.addIssuer(issuing.getCACertificateDER());
            await cm.addRevocationList(before, "issuers");
            await cm.addRevocationList(after, "trusted");

            should(await cm.isCertificateRevoked(leaf)).eql(VerificationStatus.BadCertificateRevoked);
            should(await cm.verifyCertificate(leaf, relaxed)).eql(VerificationStatus.BadCertificateRevoked);
        });

        it("still answers RevocationUnknown when the issuer has no CRL in either store", async () => {
            const leaf = await newLeaf("no-crl");
            const cm = await emptyStore("revlookup_no_crl");
            await cm.trustCertificate(root.getCACertificateDER());
            await cm.addRevocationList(root.getCRLDER(), "trusted");
            await cm.trustCertificate(issuing.getCACertificateDER());
            should(await cm.isCertificateRevoked(leaf)).eql(VerificationStatus.BadCertificateRevocationUnknown);
        });
    });

    describe("outdated issuer", () => {
        const algorithm = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
        type Keys = Awaited<ReturnType<typeof newKeys>>;
        function newKeys() {
            return webcrypto.subtle.generateKey(
                { ...algorithm, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
                true,
                ["sign", "verify"]
            );
        }
        const DAY = 86_400_000;
        let serial = 0x200;
        async function craft(
            subject: string,
            keys: Keys,
            issuer: { name: string; keys: Keys } | undefined,
            ca: boolean,
            notAfter = new Date(Date.now() + DAY)
        ): Promise<Buffer> {
            const extensions: x509.Extension[] = [
                await x509.SubjectKeyIdentifierExtension.create(keys.publicKey, false, webcrypto as Crypto),
                await x509.AuthorityKeyIdentifierExtension.create((issuer?.keys ?? keys).publicKey, false, webcrypto as Crypto),
                new x509.BasicConstraintsExtension(ca, undefined, true)
            ];
            if (ca) {
                extensions.push(new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true));
            }
            const certificate = await x509.X509CertificateGenerator.create(
                {
                    serialNumber: (serial++).toString(16),
                    subject: `CN=${subject}`,
                    issuer: `CN=${issuer?.name ?? subject}`,
                    notBefore: new Date(Date.now() - 30 * DAY),
                    notAfter,
                    signingAlgorithm: algorithm,
                    publicKey: keys.publicKey,
                    signingKey: (issuer?.keys ?? keys).privateKey,
                    extensions
                },
                webcrypto as Crypto
            );
            return Buffer.from(certificate.rawData);
        }

        let rootCertificate: Buffer;
        let expiredCa: Buffer;
        let leaf: Buffer;
        // crafted CAs publish no CRL: revocation is not what these cases are about
        const lenient = { ...relaxed, ignoreMissingRevocationList: true };

        before(async () => {
            const [rootKeys, caKeys, leafKeys] = await Promise.all([newKeys(), newKeys(), newKeys()]);
            rootCertificate = await craft("Outdated Root", rootKeys, undefined, true);
            expiredCa = await craft(
                "Outdated Sub CA",
                caKeys,
                { name: "Outdated Root", keys: rootKeys },
                true,
                new Date(Date.now() - DAY)
            );
            leaf = await craft("Outdated Leaf", leafKeys, { name: "Outdated Sub CA", keys: caKeys }, false);
        });

        for (const where of ["trusted", "issuers"] as const) {
            describe(`expired issuing CA in the ${where} store`, () => {
                let cm: CertificateManager;
                before(async () => {
                    cm = await emptyStore(`outdated_issuer_${where}`);
                    await cm.trustCertificate(rootCertificate);
                    if (where === "trusted") await cm.trustCertificate(expiredCa);
                    else await cm.addIssuer(expiredCa);
                });

                it("is refused as BadCertificateIssuerTimeInvalid by default", async () => {
                    should(await cm.verifyCertificate(leaf, lenient)).eql(VerificationStatus.BadCertificateIssuerTimeInvalid);
                });

                it("is accepted when the caller sets acceptOutDatedIssuerCertificate", async () => {
                    should(await cm.verifyCertificate(leaf, { ...lenient, acceptOutDatedIssuerCertificate: true })).eql(
                        VerificationStatus.Good
                    );
                });
            });
        }

        it("accepting outdated issuers does not make an untrusted chain trusted", async () => {
            const cm = await emptyStore("outdated_issuer_untrusted");
            await cm.addIssuer(rootCertificate);
            await cm.addIssuer(expiredCa);
            should(await cm.verifyCertificate(leaf, { ...lenient, acceptOutDatedIssuerCertificate: true })).eql(
                VerificationStatus.BadCertificateUntrusted
            );
        });
    });
});

// --------------------------------------------------------------------------
// addRevocationList stores one CRL per issuer and folder, in the slot
// crl_[<issuer>].crl, so adding a CRL replaces the issuer's stored one.
//
// - It must not replace it with an older edition: the certificates revoked
//   in between would verify as Good again. Editions are ordered by CRL
//   Number (RFC 5280 §5.2.3) when both are signed by the same certificate
//   and carry one, by thisUpdate otherwise.
// - Only a stored CRL whose signature verifies against an issuer
//   certificate of the store can refuse a new one: a forged CRL with a huge
//   CRL Number must not lock out every genuine update.
// - The name is only a slot. A slot holding another issuer's CRL (a file
//   copied in by hand under the wrong name) is neither compared with the
//   new CRL nor overwritten: it is moved to a name of its own issuer.
// --------------------------------------------------------------------------
import fs from "node:fs";
import path from "node:path";
import { readCertificateRevocationList, toPem } from "node-opcua-crypto";
import { CertificateManager, VerificationStatus } from "node-opcua-pki";
import should from "should";
import sinon from "sinon";
import { day, makeCa, makeCrl, makeForgerKey, makeLeaf, slotOf, type TestCa } from "./_crl_test_ca";
import { beforeTest } from "./helpers";

describe("CRL editions - addRevocationList never replaces a CRL with an older one", function () {
    const testData = beforeTest(this);

    let ca: TestCa;
    let otherCa: TestCa;
    let revokedLater: Buffer;
    let otherRevoked: Buffer;
    let cm: CertificateManager;
    let location: string;
    // what the manager warns about (warningLog writes to console.log);
    // the mocha reporter keeps its own reference to console.log
    let warnings: string[];
    let consoleStub: sinon.SinonStub;
    const warned = (text: string) => warnings.some((w) => w.includes(text));

    before(async () => {
        ca = await makeCa("CRL Edition Test CA");
        otherCa = await makeCa("CRL Edition Other CA");
        revokedLater = await makeLeaf(ca, "1001");
        otherRevoked = await makeLeaf(otherCa, "2001");
    });

    beforeEach(async () => {
        warnings = [];
        consoleStub = sinon.stub(console, "log").callsFake((...args: unknown[]) => {
            warnings.push(args.map(String).join(" "));
        });
        location = path.join(testData.tmpFolder, `crl_editions_${Date.now()}`);
        cm = new CertificateManager({ location });
        await cm.initialize();
        should(await cm.addIssuer(ca.der)).eql(VerificationStatus.Good);
        should(await cm.addIssuer(otherCa.der)).eql(VerificationStatus.Good);
    });

    afterEach(async () => {
        consoleStub.restore();
        await cm.dispose();
    });

    async function reopen(): Promise<void> {
        await cm.dispose();
        cm = new CertificateManager({ location });
        await cm.initialize();
    }

    for (const target of ["issuers", "trusted"] as const) {
        const folderOf = () => (target === "trusted" ? cm.crlFolder : cm.issuersCrlFolder);
        const filesIn = () => fs.readdirSync(folderOf()).sort();
        const readStored = async (file: string) =>
            (await readCertificateRevocationList(path.join(folderOf(), file))).toString("hex");
        const storedCrl = async () => {
            const files = filesIn();
            should(files.length).eql(1, `expected one CRL file, got ${files.join(", ")}`);
            return readStored(files[0]);
        };

        describe(`target ${target}`, () => {
            const t0 = new Date(Date.now() - 10 * day);
            const t1 = new Date(Date.now() - 5 * day);

            it("refuses an older CRL Number and keeps the newer CRL", async () => {
                const edition1 = await makeCrl(ca, { crlNumber: 1n, thisUpdate: t0, revoked: [] });
                const edition2 = await makeCrl(ca, { crlNumber: 2n, thisUpdate: t1, revoked: [revokedLater] });

                should(await cm.addRevocationList(edition2, target)).eql(VerificationStatus.Good);
                should(await cm.isCertificateRevoked(revokedLater)).eql(VerificationStatus.BadCertificateRevoked);

                should(await cm.addRevocationList(edition1, target)).eql(VerificationStatus.BadSecurityChecksFailed);
                should(warned("refusing a CRL older than")).eql(true, warnings.join("\n"));
                should(await storedCrl()).eql(edition2.toString("hex"));
                should(await cm.isCertificateRevoked(revokedLater)).eql(VerificationStatus.BadCertificateRevoked);
            });

            it("replaces an older CRL Number with a newer one", async () => {
                const edition1 = await makeCrl(ca, { crlNumber: 1n, thisUpdate: t0, revoked: [] });
                const edition2 = await makeCrl(ca, { crlNumber: 2n, thisUpdate: t1, revoked: [revokedLater] });

                should(await cm.addRevocationList(edition1, target)).eql(VerificationStatus.Good);
                should(await cm.isCertificateRevoked(revokedLater)).eql(VerificationStatus.Good);

                should(await cm.addRevocationList(edition2, target)).eql(VerificationStatus.Good);
                should(await storedCrl()).eql(edition2.toString("hex"));
                should(await cm.isCertificateRevoked(revokedLater)).eql(VerificationStatus.BadCertificateRevoked);
            });

            it("orders by CRL Number, not by thisUpdate, when both CRLs carry one", async () => {
                // edition 2 signed with an earlier thisUpdate than edition 1
                const edition1 = await makeCrl(ca, { crlNumber: 1n, thisUpdate: t1, revoked: [] });
                const edition2 = await makeCrl(ca, { crlNumber: 2n, thisUpdate: t0, revoked: [revokedLater] });

                should(await cm.addRevocationList(edition2, target)).eql(VerificationStatus.Good);
                should(await cm.addRevocationList(edition1, target)).eql(VerificationStatus.BadSecurityChecksFailed);
                should(await cm.isCertificateRevoked(revokedLater)).eql(VerificationStatus.BadCertificateRevoked);
            });

            it("orders by thisUpdate when a CRL has no CRL Number", async () => {
                const older = await makeCrl(ca, { thisUpdate: t0, revoked: [] });
                const newer = await makeCrl(ca, { thisUpdate: t1, revoked: [revokedLater] });

                should(await cm.addRevocationList(newer, target)).eql(VerificationStatus.Good);
                should(await cm.addRevocationList(older, target)).eql(VerificationStatus.BadSecurityChecksFailed);
                should(await cm.isCertificateRevoked(revokedLater)).eql(VerificationStatus.BadCertificateRevoked);
            });

            it("accepts the same edition again", async () => {
                const edition2 = await makeCrl(ca, { crlNumber: 2n, thisUpdate: t1, revoked: [revokedLater] });

                should(await cm.addRevocationList(edition2, target)).eql(VerificationStatus.Good);
                should(await cm.addRevocationList(edition2, target)).eql(VerificationStatus.Good);
                should(await cm.isCertificateRevoked(revokedLater)).eql(VerificationStatus.BadCertificateRevoked);
            });

            it("refuses a CRL older than a legacy crl_[<issuer>].pem, and keeps that file", async () => {
                const edition1 = await makeCrl(ca, { crlNumber: 1n, thisUpdate: t0, revoked: [] });
                const edition2 = await makeCrl(ca, { crlNumber: 2n, thisUpdate: t1, revoked: [revokedLater] });
                await cm.dispose();
                fs.writeFileSync(path.join(folderOf(), slotOf(edition2, ".pem")), toPem(edition2, "X509 CRL"), "ascii");
                cm = new CertificateManager({ location });
                await cm.initialize();

                should(await cm.addRevocationList(edition1, target)).eql(VerificationStatus.BadSecurityChecksFailed);
                should(filesIn()).eql([slotOf(edition2, ".pem")]);
                should(await cm.isCertificateRevoked(revokedLater)).eql(VerificationStatus.BadCertificateRevoked);
            });

            it("lets a genuine CRL replace a forged one carrying a higher CRL Number", async () => {
                // same issuer name as the CA, so it lands in the CA's slot
                const forged = await makeCrl(ca, {
                    crlNumber: 2n ** 120n,
                    thisUpdate: t1,
                    revoked: [],
                    signingKey: await makeForgerKey()
                });
                const genuine = await makeCrl(ca, { crlNumber: 2n, thisUpdate: t1, revoked: [revokedLater] });

                should(await cm.addRevocationList(forged, target)).eql(VerificationStatus.Good);
                should(await cm.addRevocationList(genuine, target)).eql(VerificationStatus.Good);
                should(await storedCrl()).eql(genuine.toString("hex"));
                should(await cm.isCertificateRevoked(revokedLater)).eql(VerificationStatus.BadCertificateRevoked);
            });

            it("orders by thisUpdate the CRLs of a re-keyed CA that restarted its CRL Numbers", async () => {
                // same name, new key: the issuer key of the index is the name
                const rekeyed = await makeCa("CRL Edition Test CA");
                should(await cm.addIssuer(rekeyed.der)).eql(VerificationStatus.Good);
                const revokedByNewKey = await makeLeaf(rekeyed, "3001");
                const oldKeyCrl = await makeCrl(ca, { crlNumber: 7n, thisUpdate: t0, revoked: [] });
                const newKeyCrl = await makeCrl(rekeyed, { crlNumber: 1n, thisUpdate: t1, revoked: [revokedByNewKey] });

                should(await cm.addRevocationList(oldKeyCrl, target)).eql(VerificationStatus.Good);
                should(await cm.addRevocationList(newKeyCrl, target)).eql(VerificationStatus.Good);
                should(await storedCrl()).eql(newKeyCrl.toString("hex"));
                should(await cm.isCertificateRevoked(revokedByNewKey)).eql(VerificationStatus.BadCertificateRevoked);

                // and the old key's CRL, signed earlier, does not come back
                should(await cm.addRevocationList(oldKeyCrl, target)).eql(VerificationStatus.BadSecurityChecksFailed);
            });

            it("is not blocked after clearRevocationLists, as a TrustList update replaces every CRL", async () => {
                const edition1 = await makeCrl(ca, { crlNumber: 1n, thisUpdate: t0, revoked: [] });
                const edition2 = await makeCrl(ca, { crlNumber: 2n, thisUpdate: t1, revoked: [revokedLater] });

                should(await cm.addRevocationList(edition2, target)).eql(VerificationStatus.Good);
                await cm.clearRevocationLists(target);
                should(await cm.addRevocationList(edition1, target)).eql(VerificationStatus.Good);
                should(await storedCrl()).eql(edition1.toString("hex"));
            });

            it("replaces a slot file that is not a CRL", async () => {
                const edition1 = await makeCrl(ca, { crlNumber: 1n, thisUpdate: t0, revoked: [revokedLater] });
                fs.writeFileSync(path.join(folderOf(), slotOf(edition1)), "not a CRL");

                should(await cm.addRevocationList(edition1, target)).eql(VerificationStatus.Good);
                should(await storedCrl()).eql(edition1.toString("hex"));
                should(await cm.isCertificateRevoked(revokedLater)).eql(VerificationStatus.BadCertificateRevoked);
            });

            it("fails, and leaves the slot alone, when the slot exists but cannot be read", async () => {
                const edition1 = await makeCrl(ca, { crlNumber: 1n, thisUpdate: t0, revoked: [revokedLater] });
                // a directory under the slot's name: reading it fails with EISDIR, not ENOENT
                const slot = path.join(folderOf(), slotOf(edition1));
                fs.mkdirSync(slot);

                should(await cm.addRevocationList(edition1, target)).eql(VerificationStatus.BadSecurityChecksFailed);
                should(fs.statSync(slot).isDirectory()).eql(true);
                should(await cm.isCertificateRevoked(revokedLater)).eql(VerificationStatus.BadCertificateRevocationUnknown);
            });

            describe("a slot holding another issuer's CRL", () => {
                let ownCrl: Buffer;
                let otherCrl: Buffer;

                beforeEach(async () => {
                    ownCrl = await makeCrl(ca, { crlNumber: 1n, thisUpdate: t0, revoked: [] });
                    // a later, verifiable edition of ANOTHER issuer: compared
                    // with ownCrl by mistake, it would refuse it
                    otherCrl = await makeCrl(otherCa, { crlNumber: 5n, thisUpdate: t1, revoked: [otherRevoked] });
                    await cm.dispose();
                    fs.writeFileSync(path.join(folderOf(), slotOf(ownCrl)), otherCrl);
                    cm = new CertificateManager({ location });
                    await cm.initialize();
                    // indexed by the issuer it names inside, whatever the file name
                    should(await cm.isCertificateRevoked(otherRevoked)).eql(VerificationStatus.BadCertificateRevoked);
                    should(await cm.isCertificateRevoked(revokedLater)).eql(VerificationStatus.BadCertificateRevocationUnknown);
                    // and the misnamed file is reported when it is loaded
                    should(warned(`${slotOf(ownCrl)} holds a CRL of issuer`)).eql(true, warnings.join("\n"));
                });

                it("moves it to its own issuer's slot instead of comparing or overwriting it", async () => {
                    should(await cm.addRevocationList(ownCrl, target)).eql(VerificationStatus.Good);
                    should(warned(`moving it to ${slotOf(otherCrl)}`)).eql(true, warnings.join("\n"));

                    should(filesIn()).eql([slotOf(ownCrl), slotOf(otherCrl)].sort());
                    should(await readStored(slotOf(ownCrl))).eql(ownCrl.toString("hex"));
                    should(await readStored(slotOf(otherCrl))).eql(otherCrl.toString("hex"));
                    should(await cm.isCertificateRevoked(revokedLater)).eql(VerificationStatus.Good);
                    should(await cm.isCertificateRevoked(otherRevoked)).eql(VerificationStatus.BadCertificateRevoked);

                    // the layout survives a restart
                    await reopen();
                    should(await cm.isCertificateRevoked(otherRevoked)).eql(VerificationStatus.BadCertificateRevoked);
                });

                it("keeps both files when its own issuer's slot is taken", async () => {
                    const otherOlder = await makeCrl(otherCa, { crlNumber: 4n, thisUpdate: t0, revoked: [] });
                    should(await cm.addRevocationList(otherOlder, target)).eql(VerificationStatus.Good);

                    should(await cm.addRevocationList(ownCrl, target)).eql(VerificationStatus.Good);

                    const files = filesIn();
                    should(files.length).eql(3, files.join(", "));
                    should(files).containEql(slotOf(ownCrl));
                    should(files).containEql(slotOf(otherCrl));
                    should(files.some((f) => f.startsWith(slotOf(otherCrl).replace(/\.crl$/, "_")))).eql(true, files.join(", "));
                    // the later edition of the other issuer still counts
                    should(await cm.isCertificateRevoked(otherRevoked)).eql(VerificationStatus.BadCertificateRevoked);
                });
            });
        });
    }
});

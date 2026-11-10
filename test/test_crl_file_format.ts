// --------------------------------------------------------------------------
// The CRL file that addRevocationList writes must be one that a reader of
// the PKI store finds as a CRL. Store readers (an OPC UA TrustList server
// building trustedCrls / issuerCrls is one) dispatch on the extension:
// `.crl` holds a CRL, `.pem` / `.der` hold certificates. A CRL saved as
// `crl_[<issuer>].pem` is read as a certificate chain with no certificate
// in it and comes out empty, so a client installing that TrustList rejects
// every certificate of the CA with BadCertificateRevocationUnknown.
//
// Stores written by earlier versions still hold `crl_[<issuer>].pem`: the
// CertificateManager keeps reading them, and replaces one when a new CRL of
// the same issuer is added.
// --------------------------------------------------------------------------
import fs from "node:fs";
import path from "node:path";
import {
    exploreCertificateRevocationList,
    readCertificateChainAsync,
    readCertificateRevocationList,
    toPem
} from "node-opcua-crypto";
import { CertificateManager, VerificationStatus } from "node-opcua-pki";
import should from "should";
import { day, makeCa, makeCrl, makeLeaf, type TestCa } from "./_crl_test_ca";
import { beforeTest } from "./helpers";

describe("CRL file format - addRevocationList writes a file store readers take as a CRL", function () {
    const testData = beforeTest(this);

    const fixtures = path.join(__dirname, "fixtures/CTT_sample_certificates/CA");
    const caCertificateFilename = path.join(fixtures, "certs/ctt_ca1I.der");
    const goodCertificateFilename = path.join(fixtures, "certs/ctt_ca1I_appT.der");
    const revokedCertificateFilename = path.join(fixtures, "certs/ctt_ca1I_appTR.der");
    const crlFilename = path.join(fixtures, "crl/ctt_ca1I.crl");

    let caCertificate: Buffer;
    let goodCertificate: Buffer;
    let revokedCertificate: Buffer;
    let crl: Buffer;
    let location: string;
    let cm: CertificateManager | undefined;

    before(async () => {
        caCertificate = (await readCertificateChainAsync(caCertificateFilename))[0];
        goodCertificate = (await readCertificateChainAsync(goodCertificateFilename))[0];
        revokedCertificate = (await readCertificateChainAsync(revokedCertificateFilename))[0];
        crl = await readCertificateRevocationList(crlFilename);
    });

    beforeEach(() => {
        location = path.join(testData.tmpFolder, `crl_file_format_${Date.now()}`);
    });

    afterEach(async () => {
        await cm?.dispose();
        cm = undefined;
    });

    async function openManager(): Promise<CertificateManager> {
        await cm?.dispose();
        cm = new CertificateManager({ location });
        await cm.initialize();
        await cm.addIssuer(caCertificate);
        return cm;
    }

    /** What a store reader dispatching on the extension gets from a folder. */
    async function readStoreFolder(folder: string): Promise<{ crls: Buffer[]; certificates: Buffer[] }> {
        const crls: Buffer[] = [];
        const certificates: Buffer[] = [];
        for (const file of fs.readdirSync(folder)) {
            const filename = path.join(folder, file);
            const ext = path.extname(file);
            if (ext === ".crl") {
                crls.push(await readCertificateRevocationList(filename));
            } else if (ext === ".pem" || ext === ".der") {
                certificates.push(Buffer.concat(await readCertificateChainAsync(filename)));
            }
        }
        return { crls, certificates };
    }

    async function shouldCheckAgainstTheCrl(manager: CertificateManager): Promise<void> {
        should(await manager.isCertificateRevoked(goodCertificate)).eql(VerificationStatus.Good);
        should(await manager.isCertificateRevoked(revokedCertificate)).eql(VerificationStatus.BadCertificateRevoked);
    }

    function legacyFilename(folder: string): string {
        const issuer = exploreCertificateRevocationList(crl).tbsCertList.issuerFingerprint.replace(/:/g, "");
        return path.join(folder, `crl_[${issuer}].pem`);
    }

    for (const target of ["issuers", "trusted"] as const) {
        const folderOf = (m: CertificateManager) => (target === "trusted" ? m.crlFolder : m.issuersCrlFolder);

        it(`${target}: saves the CRL as a .crl file that a store reader returns as that CRL`, async () => {
            const manager = await openManager();
            should(await manager.addRevocationList(crl, target)).eql(VerificationStatus.Good);

            const files = fs.readdirSync(folderOf(manager));
            should(files.length).eql(1, `expected one CRL file, got ${files.join(", ")}`);
            should(path.extname(files[0])).eql(".crl");

            const { crls, certificates } = await readStoreFolder(folderOf(manager));
            should(certificates.length).eql(0);
            should(crls.length).eql(1);
            should(crls[0].toString("hex")).eql(crl.toString("hex"));

            await shouldCheckAgainstTheCrl(manager);

            // a manager opened later on the same store loads it from disk
            await shouldCheckAgainstTheCrl(await openManager());
        });

        it(`${target}: keeps reading a crl_[<issuer>].pem written by an earlier version, and replaces it on add`, async () => {
            const folder = folderOf(await openManager());
            await cm?.dispose();
            cm = undefined;
            fs.writeFileSync(legacyFilename(folder), toPem(crl, "X509 CRL"), "ascii");

            const manager = await openManager();
            await shouldCheckAgainstTheCrl(manager);

            should(await manager.addRevocationList(crl, target)).eql(VerificationStatus.Good);
            should(fs.existsSync(legacyFilename(folder))).eql(false);
            const files = fs.readdirSync(folder);
            should(files.length).eql(1, `expected one CRL file, got ${files.join(", ")}`);
            should(path.extname(files[0])).eql(".crl");
            await shouldCheckAgainstTheCrl(manager);
        });

        it(`${target}: clearRevocationLists removes a crl_[<issuer>].pem written by an earlier version`, async () => {
            const manager = await openManager();
            const folder = folderOf(manager);
            fs.writeFileSync(legacyFilename(folder), toPem(crl, "X509 CRL"), "ascii");

            await manager.clearRevocationLists(target);

            should(fs.readdirSync(folder)).eql([]);
            should(await manager.isCertificateRevoked(goodCertificate)).eql(VerificationStatus.BadCertificateRevocationUnknown);
        });

        it(`${target}: clearRevocationLists removes a CRL copied in under any extension, as it counted`, async () => {
            const folder = folderOf(await openManager());
            await cm?.dispose();
            cm = undefined;
            fs.writeFileSync(path.join(folder, "ca-crl.txt"), toPem(crl, "X509 CRL"), "ascii");

            const manager = await openManager();
            // the manager indexes it whatever its name ...
            await shouldCheckAgainstTheCrl(manager);

            await manager.clearRevocationLists(target);

            // ... so a clear removes it, and it does not come back on restart
            should(fs.readdirSync(folder)).eql([]);
            should(await (await openManager()).isCertificateRevoked(revokedCertificate)).eql(
                VerificationStatus.BadCertificateRevocationUnknown
            );
        });
    }

    // A DER CRL under 256 bytes starts with 30 81, not 30 82: readers that
    // test for 30 82 take it for PEM and get nothing. An EC CA with few
    // revoked certificates publishes CRLs that short.
    describe("a CRL shorter than 256 bytes (EC CA)", () => {
        let ecCa: TestCa;
        let ecRevoked: Buffer;
        let ecGood: Buffer;
        let shortCrl: Buffer;

        before(async () => {
            ecCa = await makeCa("Short CRL EC CA", "ec");
            ecRevoked = await makeLeaf(ecCa, "51");
            ecGood = await makeLeaf(ecCa, "52");
            shortCrl = await makeCrl(ecCa, { crlNumber: 1n, thisUpdate: new Date(Date.now() - day), revoked: [ecRevoked] });
            should(shortCrl.length).be.below(256);
            should(shortCrl[1]).eql(0x81);
        });

        async function openEcManager(): Promise<CertificateManager> {
            await cm?.dispose();
            cm = new CertificateManager({ location });
            await cm.initialize();
            await cm.addIssuer(ecCa.der);
            return cm;
        }

        it("addRevocationList stores it so that the manager and a store reader both find it", async () => {
            const manager = await openEcManager();
            should(await manager.addRevocationList(shortCrl)).eql(VerificationStatus.Good);

            should(await manager.isCertificateRevoked(ecRevoked)).eql(VerificationStatus.BadCertificateRevoked);
            should(await manager.isCertificateRevoked(ecGood)).eql(VerificationStatus.Good);

            const { crls, certificates } = await readStoreFolder(manager.issuersCrlFolder);
            should(certificates.length).eql(0);
            should(crls.map((c) => c.toString("hex"))).eql([shortCrl.toString("hex")]);

            const reopened = await openEcManager();
            should(await reopened.isCertificateRevoked(ecRevoked)).eql(VerificationStatus.BadCertificateRevoked);
        });

        it("the manager reads it when it was copied in as DER", async () => {
            const folder = (await openEcManager()).issuersCrlFolder;
            await cm?.dispose();
            cm = undefined;
            fs.writeFileSync(path.join(folder, "copied_by_hand.crl"), shortCrl);

            const manager = await openEcManager();
            should(await manager.isCertificateRevoked(ecRevoked)).eql(VerificationStatus.BadCertificateRevoked);
            should(await manager.isCertificateRevoked(ecGood)).eql(VerificationStatus.Good);
        });

        // nextUpdate is OPTIONAL in the TBSCertList; a CRL without it was
        // refused (explored with revokedCertificates at its index)
        it("addRevocationList stores a CRL without nextUpdate, and it counts", async () => {
            const noNextUpdate = await makeCrl(ecCa, {
                crlNumber: 2n,
                thisUpdate: new Date(Date.now() - day),
                revoked: [ecRevoked],
                nextUpdate: false
            });
            const manager = await openEcManager();
            should(await manager.addRevocationList(noNextUpdate)).eql(VerificationStatus.Good);
            should(await manager.isCertificateRevoked(ecRevoked)).eql(VerificationStatus.BadCertificateRevoked);
            should(await manager.isCertificateRevoked(ecGood)).eql(VerificationStatus.Good);
        });
    });
});

// --------------------------------------------------------------------------
// A watcher "unlink" event can be handled after the file was written again
// under the same name: clearRevocationLists + addRevocationList puts back
// crl_[<issuer>].pem, removeIssuer + addIssuer puts back the same
// issuer_<name>.pem. The late event must not drop the entry that the
// explicit add has just indexed, or every certificate of that issuer
// answers BadCertificateRevocationUnknown until the next "add" event.
//
// The late event is delivered by hand on the CertificateManager's own
// chokidar watcher, so the test does not depend on file-system timing.
// --------------------------------------------------------------------------
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { makeSHA1Thumbprint, readCertificateChainAsync } from "node-opcua-crypto";
import { CertificateManager, VerificationStatus } from "node-opcua-pki";
import should from "should";
import sinon from "sinon";
import { beforeTest } from "./helpers";

type Chokidar = typeof import("chokidar")["default"];
type ChokidarWatcher = ReturnType<Chokidar["watch"]>;

describe("CertificateManager - watcher unlink event handled after the file was written again", function () {
    const testData = beforeTest(this);

    const fixtures = path.join(__dirname, "fixtures/CTT_sample_certificates/CA");
    const caCertificateFilename = path.join(fixtures, "certs/ctt_ca1I.der");
    const goodCertificateFilename = path.join(fixtures, "certs/ctt_ca1I_appT.der");
    const revokedCertificateFilename = path.join(fixtures, "certs/ctt_ca1I_appTR.der");
    const crlFilename = path.join(fixtures, "crl/ctt_ca1I.crl");

    // chokidar ships a CJS and an ESM build; which one CertificateManager
    // gets depends on how the loader runs it, so spy on both
    let chokidarInstances: Chokidar[];
    let watchSpies: sinon.SinonSpy<Parameters<Chokidar["watch"]>, ChokidarWatcher>[];
    let cm: CertificateManager;
    let caCertificate: Buffer;
    let goodCertificate: Buffer;
    let revokedCertificate: Buffer;

    before(async () => {
        const esm = (await import("chokidar")).default;
        const cjs = (createRequire(__filename)("chokidar") as { default: Chokidar }).default;
        chokidarInstances = [...new Set([esm, cjs])];
        caCertificate = (await readCertificateChainAsync(caCertificateFilename))[0];
        goodCertificate = (await readCertificateChainAsync(goodCertificateFilename))[0];
        revokedCertificate = (await readCertificateChainAsync(revokedCertificateFilename))[0];
    });

    beforeEach(async () => {
        watchSpies = chokidarInstances.map((c) => sinon.spy(c, "watch"));
        cm = new CertificateManager({ location: path.join(testData.tmpFolder, `late_unlink_${Date.now()}`) });
        await cm.initialize();
        await cm.addIssuer(caCertificate);
    });

    afterEach(async () => {
        for (const spy of watchSpies) {
            spy.restore();
        }
        await cm.dispose();
    });

    function watcherOf(folder: string): ChokidarWatcher {
        const call = watchSpies.flatMap((spy) => spy.getCalls()).find((c) => c.args[0] === folder);
        if (!call) {
            throw new Error(`no chokidar watcher on ${folder}`);
        }
        return call.returnValue;
    }

    function onlyFileIn(folder: string): string {
        const files = fs.readdirSync(folder);
        should(files.length).eql(1, `expected exactly one file in ${folder}, got ${files.join(", ")}`);
        return path.join(folder, files[0]);
    }

    describe("CRL", () => {
        beforeEach(async () => {
            should(await cm.addRevocationList(fs.readFileSync(crlFilename))).eql(VerificationStatus.Good);
            should(await cm.isCertificateRevoked(goodCertificate)).eql(VerificationStatus.Good);
            should(await cm.isCertificateRevoked(revokedCertificate)).eql(VerificationStatus.BadCertificateRevoked);
        });

        it("keeps a CRL that clearRevocationLists + addRevocationList wrote back under the same name", async () => {
            const before = onlyFileIn(cm.issuersCrlFolder);

            await cm.clearRevocationLists("issuers");
            should(await cm.addRevocationList(fs.readFileSync(crlFilename))).eql(VerificationStatus.Good);
            const filename = onlyFileIn(cm.issuersCrlFolder);
            should(filename).eql(before);

            // the unlink of the cleared file, delivered after the add
            watcherOf(cm.issuersCrlFolder).emit("unlink", filename);

            should(await cm.isCertificateRevoked(goodCertificate)).eql(VerificationStatus.Good);
            should(await cm.isCertificateRevoked(revokedCertificate)).eql(VerificationStatus.BadCertificateRevoked);
        });

        it("still drops a CRL whose file was deleted out of band", async () => {
            const filename = onlyFileIn(cm.issuersCrlFolder);
            fs.unlinkSync(filename);

            watcherOf(cm.issuersCrlFolder).emit("unlink", filename);

            should(await cm.isCertificateRevoked(goodCertificate)).eql(VerificationStatus.BadCertificateRevocationUnknown);
        });
    });

    describe("certificate", () => {
        let filename: string;
        const thumbprint = () => makeSHA1Thumbprint(caCertificate).toString("hex");

        beforeEach(() => {
            filename = onlyFileIn(cm.issuersCertFolder);
            // what the watcher reports for the file addIssuer wrote
            watcherOf(cm.issuersCertFolder).emit("add", filename);
            should(fs.existsSync(filename)).eql(true);
        });

        it("keeps an issuer certificate that removeIssuer + addIssuer wrote back under the same name", async () => {
            should(await cm.removeIssuer(thumbprint())).not.eql(null);
            await cm.addIssuer(caCertificate);
            should(onlyFileIn(cm.issuersCertFolder)).eql(filename);

            // the unlink of the removed file, delivered after the add
            watcherOf(cm.issuersCertFolder).emit("unlink", filename);

            should(await cm.hasIssuer(thumbprint())).eql(true);
            should(await cm.isCertificateRevoked(goodCertificate)).not.eql(VerificationStatus.BadCertificateChainIncomplete);
        });

        it("still drops an issuer certificate deleted out of band", async () => {
            fs.unlinkSync(filename);

            watcherOf(cm.issuersCertFolder).emit("unlink", filename);

            should(await cm.hasIssuer(thumbprint())).eql(false);
        });
    });
});

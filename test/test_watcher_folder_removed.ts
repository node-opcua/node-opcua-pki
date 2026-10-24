// --------------------------------------------------------------------------
// Deleting a folder that a CertificateManager watches (issue #52)
// --------------------------------------------------------------------------
//
// On Windows the native fs.watch handle of a deleted directory keeps
// reporting `rename` without end. Each report runs chokidar's
// NodeFsHandler._handleRead, which arms a *ref'd* 1 s timer in
// FSWatcher._throttle: thousands of them per second, so the process
// can no longer exit. The CertificateManager must stop watching a
// folder that is gone, forget what it held, and watch it again when
// it comes back.
//
// The storm is measured, not waited for: the test counts the timers
// chokidar creates in the seconds after the folder is removed, so a
// regression fails here instead of hanging the mocha run.
// --------------------------------------------------------------------------
import fs from "node:fs";
import path from "node:path";
import { CertificateManager, VerificationStatus } from "node-opcua-pki";
import should from "should";
import { beforeTest, waitUntil } from "./helpers";

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** Count the timers chokidar creates while `action` runs. */
async function countChokidarTimers(action: () => Promise<void>): Promise<number> {
    const originalSetTimeout = global.setTimeout;
    let count = 0;
    const counting = ((...args: Parameters<typeof setTimeout>) => {
        if (new Error().stack?.includes("chokidar")) {
            count++;
        }
        return originalSetTimeout(...args);
    }) as typeof setTimeout;
    global.setTimeout = counting;
    try {
        await action();
    } finally {
        global.setTimeout = originalSetTimeout;
    }
    return count;
}

const fixtures = path.join(__dirname, "fixtures/CTT_sample_certificates/CA");
const caCertificateFilename = path.join(fixtures, "certs/ctt_ca1I.der");
const goodCertificateFilename = path.join(fixtures, "certs/ctt_ca1I_appT.der");
const revokedCertificateFilename = path.join(fixtures, "certs/ctt_ca1I_appTR.der");
const crlFilename = path.join(fixtures, "crl/ctt_ca1I.crl");

// well above what a quiet watcher creates, far below the thousands of the storm
const MAX_CHOKIDAR_TIMERS = 20;

for (const usePolling of [false, true]) {
    describe(`CertificateManager - a watched folder is deleted (${usePolling ? "polling" : "native"} watcher)`, function () {
        this.timeout(60_000);
        const testData = beforeTest(this);

        let savedPolling: string | undefined;
        let cm: CertificateManager;
        let revokedCertificate: Buffer;

        before(() => {
            savedPolling = process.env.OPCUA_PKI_USE_POLLING;
            process.env.OPCUA_PKI_USE_POLLING = usePolling ? "true" : "false";
            revokedCertificate = fs.readFileSync(revokedCertificateFilename);
        });
        after(() => {
            if (savedPolling === undefined) {
                delete process.env.OPCUA_PKI_USE_POLLING;
            } else {
                process.env.OPCUA_PKI_USE_POLLING = savedPolling;
            }
        });

        beforeEach(async () => {
            const location = path.join(testData.tmpFolder, `folder_removed_${usePolling ? "poll" : "native"}_${Date.now()}`);
            // the files are on disk before initialize(), as in a store a
            // process starts on
            const put = (folder: string, source: string) => {
                fs.mkdirSync(path.join(location, folder), { recursive: true });
                fs.copyFileSync(source, path.join(location, folder, path.basename(source)));
            };
            put("trusted/certs", goodCertificateFilename);
            put("issuers/certs", caCertificateFilename);
            put("issuers/crl", crlFilename);

            cm = new CertificateManager({ location });
            // the interval at which a deleted folder is looked for again
            cm.folderPollingInterval = 200;
            await cm.initialize();
            // let the watchers finish their initial scan
            await sleep(1500);

            should(cm.getTrustedCertificateCount()).eql(1);
            should(await cm.isCertificateRevoked(revokedCertificate)).eql(VerificationStatus.BadCertificateRevoked);
        });

        afterEach(async () => {
            await cm.dispose();
        });

        it("stops watching a deleted certificate folder and forgets its certificates", async () => {
            const timers = await countChokidarTimers(async () => {
                fs.rmSync(cm.trustedFolder, { recursive: true, force: true });
                await sleep(3000);
            });
            should(timers).be.belowOrEqual(
                MAX_CHOKIDAR_TIMERS,
                `chokidar created ${timers} timers in 3 s after the trusted folder was deleted`
            );
            should(cm.getTrustedCertificateCount()).eql(0);
        });

        it("stops watching a deleted CRL folder and forgets its CRLs", async () => {
            const timers = await countChokidarTimers(async () => {
                fs.rmSync(cm.issuersCrlFolder, { recursive: true, force: true });
                await sleep(3000);
            });
            should(timers).be.belowOrEqual(
                MAX_CHOKIDAR_TIMERS,
                `chokidar created ${timers} timers in 3 s after the issuers CRL folder was deleted`
            );
            should(await cm.isCertificateRevoked(revokedCertificate)).eql(VerificationStatus.BadCertificateRevocationUnknown);
        });

        it("watches a recreated certificate folder again", async () => {
            fs.rmSync(cm.trustedFolder, { recursive: true, force: true });
            should(await waitUntil(() => cm.getTrustedCertificateCount() === 0, { timeoutMs: 10_000 })).eql(true);

            fs.mkdirSync(cm.trustedFolder);
            fs.copyFileSync(goodCertificateFilename, path.join(cm.trustedFolder, "good.der"));
            should(await waitUntil(() => cm.getTrustedCertificateCount() === 1, { timeoutMs: 10_000 })).eql(
                true,
                "the certificate in the recreated folder was not picked up"
            );

            // a certificate added once the folder is watched again
            fs.copyFileSync(revokedCertificateFilename, path.join(cm.trustedFolder, "revoked.der"));
            should(await waitUntil(() => cm.getTrustedCertificateCount() === 2, { timeoutMs: 10_000 })).eql(
                true,
                "a certificate added to the recreated folder was not picked up"
            );
        });

        it("watches a recreated CRL folder again", async () => {
            fs.rmSync(cm.issuersCrlFolder, { recursive: true, force: true });
            await sleep(1000);
            should(await cm.isCertificateRevoked(revokedCertificate)).eql(VerificationStatus.BadCertificateRevocationUnknown);

            fs.mkdirSync(cm.issuersCrlFolder);
            fs.copyFileSync(crlFilename, path.join(cm.issuersCrlFolder, path.basename(crlFilename)));
            let status: VerificationStatus | undefined;
            const deadline = Date.now() + 10_000;
            while (Date.now() < deadline) {
                status = await cm.isCertificateRevoked(revokedCertificate);
                if (status === VerificationStatus.BadCertificateRevoked) {
                    break;
                }
                await sleep(100);
            }
            should(status).eql(VerificationStatus.BadCertificateRevoked, "the CRL in the recreated folder was not picked up");
        });
    });
}

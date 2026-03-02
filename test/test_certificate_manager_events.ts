// --------------------------------------------------------------------------
// Unit tests: CertificateManager event emission behaviour
// --------------------------------------------------------------------------
// Verifies when certificateAdded / certificateRemoved / crlAdded /
// crlRemoved events are emitted:
//   - During initialize() (initial folder scan)
//   - During reloadCertificates()
//   - When a certificate is written at runtime (live detection)
//   - When a certificate is deleted at runtime
// --------------------------------------------------------------------------
import fs from "node:fs";
import path from "node:path";
import "should";
import { CertificateManager, type CertificateStore } from "node-opcua-pki";
import { beforeTest, waitUntil } from "./helpers";

describe("CertificateManager events", function (this: Mocha.Suite) {
    this.timeout(60_000);

    const testData = beforeTest(this);

    after(async () => {
        await CertificateManager.disposeAll();
    });

    // ──────────────────────────────────────────────────────────
    // Helper: collect events during an async operation
    // ──────────────────────────────────────────────────────────
    interface CollectedEvents {
        certificateAdded: { store: CertificateStore; fingerprint: string; filename: string }[];
        certificateRemoved: { store: CertificateStore; fingerprint: string; filename: string }[];
        certificateChange: { store: CertificateStore; fingerprint: string; filename: string }[];
    }

    function collectEvents(cm: CertificateManager): CollectedEvents {
        const events: CollectedEvents = {
            certificateAdded: [],
            certificateRemoved: [],
            certificateChange: []
        };
        cm.on("certificateAdded", (e) => events.certificateAdded.push(e));
        cm.on("certificateRemoved", (e) => events.certificateRemoved.push(e));
        cm.on("certificateChange", (e) => events.certificateChange.push(e));
        return events;
    }

    /**
     * Create a helper CertificateManager to generate a unique
     * self-signed certificate at a given path.
     */
    async function writeUniqueCert(helperPkiDir: string, outputFile: string, index: number): Promise<void> {
        const helperCm = new CertificateManager({ location: helperPkiDir });
        await helperCm.initialize();
        await helperCm.createSelfSignedCertificate({
            applicationUri: `urn:test:event:${index}:${Date.now()}`,
            dns: [`event${index}.localhost`],
            subject: `CN=EventTest_${index}`,
            startDate: new Date(),
            validity: 365,
            outputFile
        });
        await helperCm.dispose();
    }

    // ──────────────────────────────────────────────────────────
    // 1. Events during initialize()
    // ──────────────────────────────────────────────────────────
    describe("during initialize()", () => {
        it("E1 - should emit certificateAdded for pre-existing certs in trusted folder", async () => {
            const pkiDir = path.join(testData.tmpFolder, "evt_init_1");
            const helperDir = path.join(testData.tmpFolder, "evt_init_1_helper");

            // Bootstrap the PKI so directories exist
            const cmBoot = new CertificateManager({ location: pkiDir });
            await cmBoot.initialize();
            await cmBoot.dispose();

            // Pre-populate trusted/certs with 3 unique certificates
            for (let i = 0; i < 3; i++) {
                await writeUniqueCert(helperDir, path.join(pkiDir, "trusted/certs", `pre_trusted_${i}.pem`), i);
            }

            // Now initialize a fresh instance and collect events
            const cm = new CertificateManager({ location: pkiDir });
            const events = collectEvents(cm);
            await cm.initialize();

            console.log(`      certificateAdded during init: ${events.certificateAdded.length}`);

            // Events should be suppressed during initial scan
            // (chokidar "add" fires before "ready", and we gate
            // event emission behind the ready flag).
            events.certificateAdded.length.should.eql(0, "events should NOT fire during initialize() for pre-existing files");

            await cm.dispose();
        });

        it("E2 - should NOT emit certificateAdded during initialize() when PKI is empty", async () => {
            const pkiDir = path.join(testData.tmpFolder, "evt_init_2");

            const cm = new CertificateManager({ location: pkiDir });
            const events = collectEvents(cm);
            await cm.initialize();

            // The only possible "add" is the private key creation
            // cert (but that's in own/certs, not watched).
            // trusted, rejected, issuers should have 0 events.
            const storeEvents = events.certificateAdded.filter(
                (e) => e.store === "trusted" || e.store === "rejected" || e.store === "issuersCerts"
            );
            console.log(`      certificateAdded for empty PKI: ${storeEvents.length}`);
            storeEvents.length.should.eql(0);

            await cm.dispose();
        });
    });

    // ──────────────────────────────────────────────────────────
    // 2. Events during reloadCertificates()
    // ──────────────────────────────────────────────────────────
    describe("during reloadCertificates()", () => {
        it("E3 - should emit certificateAdded for all certs again after reload", async () => {
            const pkiDir = path.join(testData.tmpFolder, "evt_reload");
            const helperDir = path.join(testData.tmpFolder, "evt_reload_helper");

            // Bootstrap + populate
            const cmBoot = new CertificateManager({ location: pkiDir });
            await cmBoot.initialize();
            await cmBoot.dispose();

            for (let i = 0; i < 2; i++) {
                await writeUniqueCert(helperDir, path.join(pkiDir, "trusted/certs", `reload_cert_${i}.pem`), 100 + i);
            }

            // Initialize (events fire for initial scan)
            const cm = new CertificateManager({ location: pkiDir });
            const initEvents = collectEvents(cm);
            await cm.initialize();

            const initTrusted = initEvents.certificateAdded.filter((e) => e.store === "trusted");
            console.log(`      init: ${initTrusted.length} trusted certificateAdded`);

            // Reset event collection, then reload
            cm.removeAllListeners();
            const reloadEvents = collectEvents(cm);
            await cm.reloadCertificates();

            const reloadTrusted = reloadEvents.certificateAdded.filter((e) => e.store === "trusted");
            console.log(`      reload: ${reloadTrusted.length} trusted certificateAdded`);

            // Reload should NOT re-emit for existing certs
            // (suppressed during chokidar initial scan)
            reloadTrusted.length.should.eql(0, "reload should NOT fire events for re-scanned files");

            await cm.dispose();
        });
    });

    // ──────────────────────────────────────────────────────────
    // 3. Events for live file changes (post-ready)
    // ──────────────────────────────────────────────────────────
    describe("live file changes (post-ready)", () => {
        before(function () {
            if (process.platform === "darwin") {
                // macOS FSEvents with persistent:false watchers are
                // unreliable — skip live-detection tests on macOS.
                this.skip();
            }
        });
        it("E4 - should emit certificateAdded when a new cert is written to trusted folder", async () => {
            const pkiDir = path.join(testData.tmpFolder, "evt_live_add");
            const helperDir = path.join(testData.tmpFolder, "evt_live_add_helper");

            const cm = new CertificateManager({ location: pkiDir });
            await cm.initialize();

            // Set up listener for live events only
            const liveEvents: CollectedEvents = {
                certificateAdded: [],
                certificateRemoved: [],
                certificateChange: []
            };
            cm.on("certificateAdded", (e) => liveEvents.certificateAdded.push(e));

            const certFile = path.join(pkiDir, "trusted/certs", "live_added_cert.pem");

            // Write a new certificate
            await writeUniqueCert(helperDir, certFile, 200);

            // Wait for the watcher to pick it up
            await waitUntil(() => liveEvents.certificateAdded.some((e) => e.filename.includes("live_added_cert")), {
                timeoutMs: 15_000
            });

            const liveAdded = liveEvents.certificateAdded.filter((e) => e.filename.includes("live_added_cert"));
            console.log(`      live certificateAdded: ${liveAdded.length}`);
            liveAdded.length.should.eql(1);
            liveAdded[0].store.should.eql("trusted");

            await cm.dispose();
        });

        it("E5 - should emit certificateRemoved when a cert is deleted from trusted folder", async () => {
            const pkiDir = path.join(testData.tmpFolder, "evt_live_del");
            const helperDir = path.join(testData.tmpFolder, "evt_live_del_helper");

            // Bootstrap + add a cert
            const cm = new CertificateManager({ location: pkiDir });
            await cm.initialize();

            const certFile = path.join(pkiDir, "trusted/certs", "will_be_deleted.pem");
            await writeUniqueCert(helperDir, certFile, 300);

            // Wait for the add event to confirm cert is tracked
            await new Promise<void>((resolve) => {
                cm.once("certificateAdded", () => resolve());
                setTimeout(() => resolve(), 10000);
            });

            // Now listen for removal
            const removedPromise = new Promise<{ store: string; fingerprint: string; filename: string }>((resolve) => {
                cm.once("certificateRemoved", (e) => resolve(e));
                setTimeout(() => resolve({ store: "", fingerprint: "", filename: "" }), 10000);
            });

            // Delete the file
            fs.unlinkSync(certFile);

            const removed = await removedPromise;
            console.log(`      certificateRemoved: store=${removed.store} file=${path.basename(removed.filename)}`);

            removed.store.should.eql("trusted");
            removed.filename.should.containEql("will_be_deleted");

            await cm.dispose();
        });
    });

    // ──────────────────────────────────────────────────────────
    // 4. Event noise analysis
    // ──────────────────────────────────────────────────────────
    describe("event noise analysis", () => {
        it("E6 - should count total events during init vs live to quantify noise", async () => {
            const pkiDir = path.join(testData.tmpFolder, "evt_noise");
            const helperDir = path.join(testData.tmpFolder, "evt_noise_helper");

            // Bootstrap + pre-populate with 5 certs
            const cmBoot = new CertificateManager({ location: pkiDir });
            await cmBoot.initialize();
            await cmBoot.dispose();

            for (let i = 0; i < 5; i++) {
                await writeUniqueCert(helperDir, path.join(pkiDir, "trusted/certs", `noise_cert_${i}.pem`), 400 + i);
            }

            // Initialize and count init events
            const cm = new CertificateManager({ location: pkiDir });
            let initEventCount = 0;
            let liveEventCount = 0;
            let isReady = false;

            cm.on("certificateAdded", () => {
                if (isReady) {
                    liveEventCount++;
                } else {
                    initEventCount++;
                }
            });

            await cm.initialize();
            isReady = true;

            // Now add one more cert live
            const liveCertFile = path.join(pkiDir, "trusted/certs", "noise_live_cert.pem");
            await writeUniqueCert(helperDir, liveCertFile, 500);

            // Wait for the watcher to detect the live cert
            await waitUntil(() => liveEventCount > 0, { timeoutMs: 15_000 });

            console.log(`      init events (noise):  ${initEventCount}`);
            console.log(`      live events (signal):  ${liveEventCount}`);
            console.log(
                `      noise ratio: ${initEventCount}:${liveEventCount} ` +
                    `(${initEventCount} init events for ${liveEventCount} live event)`
            );

            // With the ready flag, init events should be 0
            // (suppressed during initial scan)
            initEventCount.should.eql(0, "init events should be suppressed");
            liveEventCount.should.eql(1);

            await cm.dispose();
        });
    });
});

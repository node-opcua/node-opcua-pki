// --------------------------------------------------------------------------
// Reproduce FSWatcher EPERM crash (Windows + Node < 22)
// --------------------------------------------------------------------------
//
// Root cause
// ──────────
// On Windows with Node < 22, fs.watch with persistent:false throws an
// uncaught EPERM when the watched directory is removed:
//
//   Error: EPERM: operation not permitted, watch
//       at FSWatcher._handle.onchange (node:internal/fs/watchers:207:21)
//
// Chokidar v4 does NOT register an 'error' handler on the underlying
// fs.watch handle when persistent:false (handler.js l.160-168), so
// the EPERM becomes an uncaught exception that crashes the process.
//
// CertificateManager uses chokidar with persistent:false to watch
// 5 directories.  When the directories are cleaned up while the
// CertificateManager is still alive, the watchers fire EPERM.
//
// On Node >= 22 and Node 24+ the EPERM does not fire, so these
// tests pass trivially on those versions.  The tests are safe
// on all platforms (uncaughtException handler prevents crash).
// --------------------------------------------------------------------------
import fs from "node:fs";
import path from "node:path";
import "should";
import { CertificateManager } from "node-opcua-pki";
import { beforeTest } from "./helpers";

describe("FSWatcher EPERM resilience", function (this: Mocha.Suite) {
    this.timeout(120_000);

    const testData = beforeTest(this);

    after(async () => {
        await CertificateManager.disposeAll();
    });

    // ──────────────────────────────────────────────────────────
    // CertificateManager — the real-world scenario
    // ──────────────────────────────────────────────────────────
    // This test reproduces the original bug: a CertificateManager
    // creates chokidar watchers (persistent:false), and when the
    // watched directories are removed (e.g. test cleanup), the
    // underlying fs.watch handles throw uncaught EPERM errors on
    // Windows + Node < 22.
    //
    // After the fix (error handlers on fs.watch handles and
    // chokidar watchers), this test must PASS.
    // ──────────────────────────────────────────────────────────
    it("should not crash when CertificateManager watched dirs are removed", async () => {
        const pkiDir = path.join(testData.tmpFolder, "eperm_cm");

        const cm = new CertificateManager({ location: pkiDir });
        await cm.initialize();

        // Give chokidar time to set up all fs.watch handles
        await new Promise<void>((resolve) => setTimeout(resolve, 500));

        const uncaughtErrors: NodeJS.ErrnoException[] = [];
        const onUncaught = (err: Error) => {
            uncaughtErrors.push(err as NodeJS.ErrnoException);
        };
        process.on("uncaughtException", onUncaught);

        try {
            // Remove the watched sub-directories (simulating test cleanup)
            const watchedDirs = [
                path.join(pkiDir, "trusted", "certs"),
                path.join(pkiDir, "trusted", "crl"),
                path.join(pkiDir, "issuers", "certs"),
                path.join(pkiDir, "issuers", "crl"),
                path.join(pkiDir, "rejected")
            ];
            for (const dir of watchedDirs) {
                await fs.promises.rm(dir, { recursive: true, force: true }).catch(() => {});
            }

            // Give time for EPERM errors to fire on the event loop
            await new Promise<void>((resolve) => setTimeout(resolve, 1000));

            const epermErrors = uncaughtErrors.filter((e) => e.code === "EPERM");
            epermErrors.length.should.eql(
                0,
                `Expected no uncaught EPERM from CertificateManager, but got ${epermErrors.length}: ` +
                    `${epermErrors.map((e) => e.message).join("; ")}`
            );
        } finally {
            process.removeListener("uncaughtException", onUncaught);
            try {
                await cm.dispose();
            } catch {
                /* swallow dispose errors on partially-deleted dirs */
            }
        }
    });

    // ──────────────────────────────────────────────────────────
    // Rapid create/destroy cycle (beforeEach/afterEach pattern)
    // ──────────────────────────────────────────────────────────
    it("should survive rapid create→init→rm→dispose cycles", async () => {
        const uncaughtErrors: NodeJS.ErrnoException[] = [];
        const onUncaught = (err: Error) => {
            uncaughtErrors.push(err as NodeJS.ErrnoException);
        };
        process.on("uncaughtException", onUncaught);

        const totalCycles = 3;
        try {
            for (let i = 0; i < totalCycles; i++) {
                const pkiDir = path.join(testData.tmpFolder, `eperm_cycle_${i}`);

                // Simulate initializeHelpers pattern: rm old + mkdir fresh
                await fs.promises.rm(pkiDir, { recursive: true, force: true }).catch(() => {});
                await fs.promises.mkdir(pkiDir, { recursive: true });

                const cm = new CertificateManager({ location: pkiDir });
                await cm.initialize();

                // Remove PKI directory while CertificateManager is alive
                // (this is the race condition)
                await fs.promises.rm(pkiDir, { recursive: true, force: true }).catch(() => {});
                await new Promise<void>((resolve) => setTimeout(resolve, 250));

                try {
                    await cm.dispose();
                } catch {
                    /* swallow */
                }
            }

            const epermErrors = uncaughtErrors.filter((e) => e.code === "EPERM");
            epermErrors.length.should.eql(0, `Expected no uncaught EPERM across ${totalCycles} cycles, got ${epermErrors.length}`);
        } finally {
            process.removeListener("uncaughtException", onUncaught);
        }
    });
});

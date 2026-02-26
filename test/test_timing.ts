// --------------------------------------------------------------------------
// Benchmark: CertificateManager.initialize() — polling vs native FS events
// --------------------------------------------------------------------------
// Usage:
//   npx mocha test/test_timing.ts
//   npx mocha test/test_timing.ts --grep "compare"
//
// The test creates a PKI directory pre-populated with N unique
// self-signed certificates in trusted/, rejected/, and
// issuers/certs/, then measures how long
// CertificateManager.initialize() takes in each chokidar mode.
// --------------------------------------------------------------------------
import fs from "node:fs";
import path from "node:path";
import { CertificateManager } from "node-opcua-pki";
import { mkdirRecursiveSync } from "node-opcua-pki-priv/toolbox/common2";

const tmpFolder = path.join(__dirname, "../tmp");

// Number of unique certificates to generate per folder.
const CERTS_PER_FOLDER = 200;

/**
 * Chokidar mode descriptor for benchmarking.
 */
interface BenchMode {
    label: string;
    usePolling: boolean;
    /** Polling interval in ms (only relevant when usePolling=true). */
    pollingInterval?: number;
}

const MODES: Record<string, BenchMode> = {
    native: { label: "native", usePolling: false },
    polling5s: { label: "polling-5s", usePolling: true, pollingInterval: 5000 },
    polling1s: { label: "polling-1s", usePolling: true, pollingInterval: 1000 }
};

/**
 * Populate a target folder with N unique certificates.
 * A helper PKI is used as the signer; its private key and
 * openssl config are created once and reused.
 */
async function populateFolderWithUniqueCerts(
    helperPkiDir: string,
    targetFolder: string,
    count: number,
    prefix: string
): Promise<void> {
    mkdirRecursiveSync(targetFolder);

    const cm = new CertificateManager({ location: helperPkiDir });
    await cm.initialize();

    for (let i = 0; i < count; i++) {
        const certFile = path.join(targetFolder, `${prefix}_${i}.pem`);
        if (!fs.existsSync(certFile)) {
            await cm.createSelfSignedCertificate({
                applicationUri: `urn:bench:${prefix}:${i}`,
                dns: [`${prefix}${i}.localhost`],
                subject: `CN=${prefix}_${i}`,
                startDate: new Date(),
                validity: 365,
                outputFile: certFile
            });
        }
    }

    await cm.dispose();
}

/**
 * Create a fresh copy of a PKI directory for benchmarking.
 * Each CertificateManager instance can only initialize() once,
 * so we need a fresh copy for each measurement.
 */
function copyPkiDir(src: string, dest: string): void {
    if (fs.existsSync(dest)) {
        fs.rmSync(dest, { recursive: true, force: true });
    }
    mkdirRecursiveSync(dest);

    // Copy all files and subdirectories recursively
    const entries = fs.readdirSync(src, { withFileTypes: true });
    for (const entry of entries) {
        const srcPath = path.join(src, entry.name);
        const destPath = path.join(dest, entry.name);
        if (entry.isDirectory()) {
            copyPkiDir(srcPath, destPath);
        } else {
            fs.copyFileSync(srcPath, destPath);
        }
    }
}

/**
 * Measure CertificateManager.initialize() duration.
 */
async function measureInitialize(pkiLocation: string, mode: BenchMode): Promise<number> {
    if (mode.usePolling) {
        process.env.OPCUA_PKI_USE_POLLING = "true";
    } else {
        delete process.env.OPCUA_PKI_USE_POLLING;
    }

    const cm = new CertificateManager({ location: pkiLocation });
    if (mode.pollingInterval !== undefined) {
        cm.folderPollingInterval = mode.pollingInterval;
    }

    const t0 = performance.now();
    await cm.initialize();
    const elapsed = performance.now() - t0;

    await cm.dispose();
    return elapsed;
}

describe("CertificateManager.initialize() timing", function (this: Mocha.Suite) {
    this.timeout(10 * 60 * 1000); // 10 min for cert generation

    const benchPkiDir = path.join(tmpFolder, "bench_pki");
    const helperPkiDir = path.join(tmpFolder, "bench_pki_helper");

    let pkiCopyIndex = 0;

    function nextPkiCopy(): string {
        const copyDir = path.join(tmpFolder, `bench_pki_run_${pkiCopyIndex++}`);
        copyPkiDir(benchPkiDir, copyDir);
        return copyDir;
    }

    async function timedInit(mode: BenchMode): Promise<number> {
        const dir = nextPkiCopy();
        try {
            return await measureInitialize(dir, mode);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    }

    before(async () => {
        await CertificateManager.disposeAll();

        // Bootstrap the benchmark PKI (creates private key
        // and config file).
        const cm = new CertificateManager({ location: benchPkiDir });
        await cm.initialize();
        await cm.dispose();

        console.log(`    Generating ${CERTS_PER_FOLDER} unique certs ` + `per folder (${CERTS_PER_FOLDER * 3} total) ...`);

        await populateFolderWithUniqueCerts(helperPkiDir, path.join(benchPkiDir, "trusted/certs"), CERTS_PER_FOLDER, "trusted");
        await populateFolderWithUniqueCerts(helperPkiDir, path.join(benchPkiDir, "rejected"), CERTS_PER_FOLDER, "rejected");
        await populateFolderWithUniqueCerts(helperPkiDir, path.join(benchPkiDir, "issuers/certs"), CERTS_PER_FOLDER, "issuer");

        // Count actual files to confirm
        const countFiles = (dir: string) => (fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith(".pem")).length : 0);

        console.log(`    trusted:  ${countFiles(path.join(benchPkiDir, "trusted/certs"))} certs`);
        console.log(`    rejected: ${countFiles(path.join(benchPkiDir, "rejected"))} certs`);
        console.log(`    issuers:  ${countFiles(path.join(benchPkiDir, "issuers/certs"))} certs`);
    });

    after(async () => {
        await CertificateManager.disposeAll();
        delete process.env.OPCUA_PKI_USE_POLLING;
    });

    it("should measure initialize() with NATIVE FS events (usePolling=false)", async () => {
        const mode = MODES.native;
        const warmup = await timedInit(mode);
        console.log(`      [${mode.label}] warm-up: ${warmup.toFixed(1)}ms`);

        const times: number[] = [];
        for (let i = 0; i < 3; i++) {
            const elapsed = await timedInit(mode);
            times.push(elapsed);
            console.log(`      [${mode.label}] run ${i + 1}: ${elapsed.toFixed(1)}ms`);
        }
        const avg = times.reduce((a, b) => a + b, 0) / times.length;
        console.log(`      [${mode.label}] average: ${avg.toFixed(1)}ms`);
    });

    it("should measure initialize() with POLLING 5s (usePolling=true, interval=5000ms)", async () => {
        const mode = MODES.polling5s;
        const warmup = await timedInit(mode);
        console.log(`      [${mode.label}] warm-up: ${warmup.toFixed(1)}ms`);

        const times: number[] = [];
        for (let i = 0; i < 3; i++) {
            const elapsed = await timedInit(mode);
            times.push(elapsed);
            console.log(`      [${mode.label}] run ${i + 1}: ${elapsed.toFixed(1)}ms`);
        }
        const avg = times.reduce((a, b) => a + b, 0) / times.length;
        console.log(`      [${mode.label}] average: ${avg.toFixed(1)}ms`);
    });

    it("should measure initialize() with POLLING 1s (usePolling=true, interval=1000ms)", async () => {
        const mode = MODES.polling1s;
        const warmup = await timedInit(mode);
        console.log(`      [${mode.label}] warm-up: ${warmup.toFixed(1)}ms`);

        const times: number[] = [];
        for (let i = 0; i < 3; i++) {
            const elapsed = await timedInit(mode);
            times.push(elapsed);
            console.log(`      [${mode.label}] run ${i + 1}: ${elapsed.toFixed(1)}ms`);
        }
        const avg = times.reduce((a, b) => a + b, 0) / times.length;
        console.log(`      [${mode.label}] average: ${avg.toFixed(1)}ms`);
    });

    it("should compare all modes side by side", async () => {
        const nativeTime = await timedInit(MODES.native);
        const polling5sTime = await timedInit(MODES.polling5s);
        const polling1sTime = await timedInit(MODES.polling1s);

        console.log("");
        console.log("    ┌──────────────────────────────────────────────────┐");
        console.log("    │  CertificateManager.initialize() benchmark       │");
        console.log("    ├──────────────────────────────────────────────────┤");
        console.log(`    │  Native FS events:     ${nativeTime.toFixed(1).padStart(8)}ms              │`);
        console.log(`    │  Polling 5s (default): ${polling5sTime.toFixed(1).padStart(8)}ms              │`);
        console.log(`    │  Polling 1s:           ${polling1sTime.toFixed(1).padStart(8)}ms              │`);
        console.log("    └──────────────────────────────────────────────────┘");
        console.log("");
    });
});

// --------------------------------------------------------------------------
// Benchmark 2: Live-detection latency
// --------------------------------------------------------------------------
// Measures how long it takes for the CertificateManager to detect
// a newly written certificate file via its chokidar watcher,
// comparing polling vs native FS event modes.
// --------------------------------------------------------------------------

describe("CertificateManager live-detection latency", function (this: Mocha.Suite) {
    this.timeout(5 * 60 * 1000);

    const benchPkiDir = path.join(tmpFolder, "bench_pki_live");
    const helperPkiDir = path.join(tmpFolder, "bench_pki_live_helper");
    let liveCopyIndex = 0;

    /**
     * Measure the latency between writing a certificate file
     * and receiving the "certificateAdded" event.
     */
    async function measureDetectionLatency(mode: BenchMode, runs: number): Promise<number[]> {
        const times: number[] = [];

        for (let i = 0; i < runs; i++) {
            // Each measurement uses a fresh PKI copy
            const copyDir = path.join(tmpFolder, `bench_live_${liveCopyIndex++}`);
            copyPkiDir(benchPkiDir, copyDir);

            if (mode.usePolling) {
                process.env.OPCUA_PKI_USE_POLLING = "true";
            } else {
                delete process.env.OPCUA_PKI_USE_POLLING;
            }

            const cm = new CertificateManager({ location: copyDir });
            if (mode.pollingInterval !== undefined) {
                cm.folderPollingInterval = mode.pollingInterval;
            }
            await cm.initialize();

            // Generate a unique cert and write it to trusted/certs
            const certFile = path.join(copyDir, "trusted/certs", `live_detection_${liveCopyIndex}_${i}.pem`);

            // Use the helper PKI to create a unique cert at the
            // target location
            const helperCm = new CertificateManager({
                location: helperPkiDir
            });
            await helperCm.initialize();

            // Wait for the detection via the "certificateAdded" event
            const detectionPromise = new Promise<number>((resolve, reject) => {
                const timeout = setTimeout(() => {
                    reject(new Error(`Detection timed out after 30s (mode=${mode.label})`));
                }, 30000);

                cm.on("certificateAdded", (event) => {
                    if (event.filename.includes(`live_detection_${liveCopyIndex}_${i}`)) {
                        clearTimeout(timeout);
                        resolve(performance.now());
                    }
                });
            });

            // Timestamp BEFORE the write — with native FS events,
            // chokidar can fire the event mid-await (before the
            // promise resolves), so capturing time after await
            // would give negative latency.
            const writeTime = performance.now();
            await helperCm.createSelfSignedCertificate({
                applicationUri: `urn:bench:live:${liveCopyIndex}:${i}`,
                dns: [`live${liveCopyIndex}.localhost`],
                subject: `CN=LiveDetection_${liveCopyIndex}_${i}`,
                startDate: new Date(),
                validity: 365,
                outputFile: certFile
            });

            const detectTime = await detectionPromise;
            const latency = detectTime - writeTime;
            times.push(latency);

            await helperCm.dispose();
            await cm.dispose();
            fs.rmSync(copyDir, { recursive: true, force: true });
        }

        return times;
    }

    before(async () => {
        await CertificateManager.disposeAll();

        // Bootstrap a minimal PKI (just private key + dirs)
        const cm = new CertificateManager({ location: benchPkiDir });
        await cm.initialize();
        await cm.dispose();

        // Bootstrap the helper PKI too
        const helperCm = new CertificateManager({
            location: helperPkiDir
        });
        await helperCm.initialize();
        await helperCm.dispose();
    });

    after(async () => {
        await CertificateManager.disposeAll();
        delete process.env.OPCUA_PKI_USE_POLLING;
    });

    it("should measure detection latency with NATIVE FS events", async () => {
        const times = await measureDetectionLatency(MODES.native, 3);
        for (let i = 0; i < times.length; i++) {
            console.log(`      [native] run ${i + 1}: ${times[i].toFixed(1)}ms`);
        }
        const avg = times.reduce((a, b) => a + b, 0) / times.length;
        console.log(`      [native] average: ${avg.toFixed(1)}ms`);
    });

    it("should measure detection latency with POLLING 5s (default)", async () => {
        const times = await measureDetectionLatency(MODES.polling5s, 3);
        for (let i = 0; i < times.length; i++) {
            console.log(`      [polling-5s] run ${i + 1}: ${times[i].toFixed(1)}ms`);
        }
        const avg = times.reduce((a, b) => a + b, 0) / times.length;
        console.log(`      [polling-5s] average: ${avg.toFixed(1)}ms`);
    });

    it("should measure detection latency with POLLING 1s", async () => {
        const times = await measureDetectionLatency(MODES.polling1s, 3);
        for (let i = 0; i < times.length; i++) {
            console.log(`      [polling-1s] run ${i + 1}: ${times[i].toFixed(1)}ms`);
        }
        const avg = times.reduce((a, b) => a + b, 0) / times.length;
        console.log(`      [polling-1s] average: ${avg.toFixed(1)}ms`);
    });

    it("should compare all live-detection modes side by side", async () => {
        const nativeTimes = await measureDetectionLatency(MODES.native, 1);
        const polling5sTimes = await measureDetectionLatency(MODES.polling5s, 1);
        const polling1sTimes = await measureDetectionLatency(MODES.polling1s, 1);

        console.log("");
        console.log("    ┌──────────────────────────────────────────────────┐");
        console.log("    │  Live-detection latency benchmark                │");
        console.log("    ├──────────────────────────────────────────────────┤");
        console.log(`    │  Native FS events:     ${nativeTimes[0].toFixed(1).padStart(8)}ms              │`);
        console.log(`    │  Polling 5s (default): ${polling5sTimes[0].toFixed(1).padStart(8)}ms              │`);
        console.log(`    │  Polling 1s:           ${polling1sTimes[0].toFixed(1).padStart(8)}ms              │`);
        console.log("    └──────────────────────────────────────────────────┘");
        console.log("");
    });
});

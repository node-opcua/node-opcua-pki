Error.stackTraceLimit = Infinity;

import path from "node:path";
import "should";
import { beforeTest } from "./helpers";

// Regression tests for #51.
//
// node-opcua-pki used to register its own SIGINT/SIGTERM
// handlers that called process.exit() unconditionally, which cut
// short (or entirely pre-empted) the host application's graceful
// shutdown. A library must never terminate the host process.
//
// These tests run in a child process because they are about
// whole-process behaviour: signal dispatch order and whether the
// process manages to exit at all.

// Use absolute path to the built dist — the child process
// doesn't have tsconfig-paths so bare require("node-opcua-pki")
// would fail on CI/Docker.
const distPath = path.resolve(__dirname, "../packages/node-opcua-pki/dist/index.js").replace(/\\/g, "/");

interface ChildResult {
    exitCode: number | null;
    stdout: string;
    stderr: string;
}

async function runChild(script: string, timeoutMs: number): Promise<ChildResult> {
    const { execFile } = await import("node:child_process");
    const cwd = path.resolve(__dirname, "..");

    return await new Promise<ChildResult>((resolve, reject) => {
        const child = execFile(process.execPath, ["-e", script], { timeout: timeoutMs, cwd }, (err, stdout, stderr) => {
            if (err && "killed" in err && err.killed) {
                reject(
                    new Error(
                        `Child process did not exit within ${timeoutMs / 1000}s.` + `\nSTDOUT: ${stdout}` + `\nSTDERR: ${stderr}`
                    )
                );
                return;
            }
            resolve({ exitCode: child.exitCode, stdout, stderr });
        });
    });
}

/**
 * An application that installs its own SIGINT handler doing
 * asynchronous shutdown work.
 *
 * `order` decides whether the application registers its handler
 * before or after `initialize()`. Both orders used to fail, in
 * different ways: registering *before* meant the shutdown was
 * started then killed mid-flight, registering *after* meant the
 * application handler never ran at all.
 *
 * The signal is raised with `process.emit("SIGINT")` rather than
 * `process.kill(process.pid, "SIGINT")`: on Windows a self-kill
 * is mapped to TerminateProcess, which tears the child down
 * before any listener runs and would make this test silently
 * vacuous.
 */
function makeGracefulShutdownScript(loc: string, order: "app-first" | "app-last"): string {
    return `
        const { CertificateManager } = require(${JSON.stringify(distPath)});

        function installAppHandler() {
            process.on("SIGINT", () => {
                console.log("APP_SIGINT_RECEIVED");
                setTimeout(() => {
                    console.log("APP_SHUTDOWN_COMPLETED");
                    process.exit(0);
                }, 200);
            });
        }

        (async () => {
            try {
                if (${JSON.stringify(order)} === "app-first") installAppHandler();

                // Measure around initialize() only. An absolute
                // count would be wrong under coverage: nyc installs
                // a SIGINT listener of its own in the child to flush
                // coverage data. What matters is that the library
                // adds none.
                const pre = {
                    SIGINT: process.listenerCount("SIGINT"),
                    SIGTERM: process.listenerCount("SIGTERM")
                };
                const cm = new CertificateManager({ location: ${JSON.stringify(loc)} });
                await cm.initialize();
                console.log("SIGINT_DELTA=" + (process.listenerCount("SIGINT") - pre.SIGINT));
                console.log("SIGTERM_DELTA=" + (process.listenerCount("SIGTERM") - pre.SIGTERM));

                if (${JSON.stringify(order)} === "app-last") installAppHandler();

                setTimeout(() => process.emit("SIGINT"), 100);
            } catch (err) {
                console.log("ERROR:", err.message);
                console.log(err.stack);
                process.exit(2);
            }
        })();
    `;
}

/**
 * An undisposed CertificateManager must not keep the event loop
 * alive — that guarantee is what makes teardown optional for the
 * consuming application.
 *
 * The subdirectory created *after* the watchers are up is the
 * interesting part: chokidar recurses without bound unless
 * `depth` is set, and descending into a new subdirectory routes
 * through _handleRead -> FSWatcher._throttle, which schedules
 * ref'd 1s timers. Enough of those keep the event loop alive and
 * the process never exits.
 *
 * Timing-dependent before the fix (chokidar does not always get
 * far enough to spin the timers), deterministic after it: with
 * depth 0 the subdirectory is never read at all.
 */
function makeLateSubdirScript(loc: string): string {
    return `
        const fs = require("node:fs");
        const path = require("node:path");
        const { CertificateManager } = require(${JSON.stringify(distPath)});

        (async () => {
            try {
                const cm = new CertificateManager({ location: ${JSON.stringify(loc)} });
                await cm.initialize();

                // Let the watchers settle, then drop a subfolder
                // into a watched store. Deliberately NOT disposing.
                setTimeout(() => {
                    fs.mkdirSync(path.join(cm.trustedFolder, "late_subdir"), { recursive: true });
                    fs.writeFileSync(path.join(cm.trustedFolder, "late_subdir", "note.txt"), "x");
                    setTimeout(() => {
                        console.log("LATE_SUBDIR_CREATED");
                    }, 1500);
                }, 1000);
            } catch (err) {
                console.log("ERROR:", err.message);
                console.log(err.stack);
                process.exit(2);
            }
        })();
    `;
}

describe("CertificateManager signal handling", function (this: Mocha.Suite) {
    this.timeout(160_000);

    const testData = beforeTest(this);

    // On WSL over /mnt/c, require() resolution is extremely slow
    // (stat calls on Windows FS from Linux), causing the child to
    // hang during module loading — not a real bug.
    const isWSLCrossMount = process.platform === "linux" && path.resolve(__dirname).startsWith("/mnt/");

    for (const order of ["app-first", "app-last"] as const) {
        it(`should let the application complete an async SIGINT shutdown (${order})`, async function () {
            if (isWSLCrossMount) {
                this.skip();
                return;
            }
            const loc = path.join(testData.tmpFolder, `SIGNAL_TEST_${order.toUpperCase().replace("-", "_")}`);
            const result = await runChild(makeGracefulShutdownScript(loc, order), 60_000);

            const diag = `\nSTDOUT: ${result.stdout}\nSTDERR: ${result.stderr}`;

            // initialize() must not add a signal listener of its own
            result.stdout.should.match(/SIGINT_DELTA=0/, `initialize() should add no SIGINT listener${diag}`);
            result.stdout.should.match(/SIGTERM_DELTA=0/, `initialize() should add no SIGTERM listener${diag}`);
            result.stdout.should.match(/APP_SIGINT_RECEIVED/, `application handler should run${diag}`);
            result.stdout.should.match(/APP_SHUTDOWN_COMPLETED/, `async shutdown should run to completion${diag}`);
            (result.exitCode ?? 1).should.eql(0, `child should exit cleanly${diag}`);
        });
    }

    it("undisposed CertificateManager should NOT prevent process exit after a late subdirectory appears", async function () {
        if (isWSLCrossMount) {
            this.skip();
            return;
        }
        const loc = path.join(testData.tmpFolder, "SIGNAL_TEST_LATE_SUBDIR");
        const result = await runChild(makeLateSubdirScript(loc), 60_000);

        const diag = `\nSTDOUT: ${result.stdout}\nSTDERR: ${result.stderr}`;
        result.stdout.should.match(/LATE_SUBDIR_CREATED/, `child should reach the end of its work${diag}`);
        (result.exitCode ?? 1).should.eql(0, `child should exit cleanly${diag}`);
    });
});

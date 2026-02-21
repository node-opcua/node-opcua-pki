Error.stackTraceLimit = Infinity;

import path from "node:path";
import "should";
import { beforeTest } from "./helpers";

function makeChildScript(loc: string, env?: Record<string, string>): string {
    const envSetup = env
        ? Object.entries(env)
              .map(([k, v]) => `process.env[${JSON.stringify(k)}] = ${JSON.stringify(v)};`)
              .join("\n")
        : "";

    // Use absolute path to the built dist — the child process
    // doesn't have tsconfig-paths so bare require("node-opcua-pki")
    // would fail on CI/Docker.
    const distPath = path.resolve(__dirname, "../packages/node-opcua-pki/dist/index.js").replace(/\\/g, "/");

    return `
        ${envSetup}
        console.log("in script; OPCUA_PKI_USE_POLLING=", process.env.OPCUA_PKI_USE_POLLING);
        console.log("scripti path", ${JSON.stringify(distPath)});
        const { CertificateManager } = require(${JSON.stringify(distPath)});
        console.log("Starting child process");
        (async () => {
            try {
                const cm = new CertificateManager({ location: ${JSON.stringify(loc)} });
                await cm.initialize();
                // Deliberately NOT calling cm.dispose()
                console.log("initialized, waiting for natural exit...");

                // Diagnostic: list active handles that keep the loop alive
                const handles = process._getActiveHandles();
                for (const h of handles) {
                    console.log("active handle:", h.constructor.name,
                        h._handle ? h._handle.constructor.name : "",
                        h.ref ? "(ref)" : "(no ref method)");
                }
            } catch (err) {
                console.log("ERROR:", err.message);
                console.log(err.stack);
                process.exit(2);
            }
        })();
    `;
}

async function runChildAndExpectExit(
    childScript: string,
    cwd: string,
    timeoutMs = 240_000 // may take long time on WSL or mounted docker
): Promise<void> {
    const { execFile } = await import("node:child_process");

    const result = await new Promise<{
        exitCode: number | null;
        stdout: string;
        stderr: string;
    }>((resolve, reject) => {
        const child = execFile(process.execPath, ["-e", childScript], { timeout: timeoutMs, cwd }, (err, stdout, stderr) => {
            if (err && "killed" in err && err.killed) {
                reject(
                    new Error(
                        "Child process did not exit within " +
                            `${timeoutMs / 1000}s — ` +
                            "undisposed CertificateManager is " +
                            "blocking exit." +
                            `\nSTDOUT: ${stdout}` +
                            `\nSTDERR: ${stderr}`
                    )
                );
            } else {
                resolve({
                    exitCode: child.exitCode,
                    stdout,
                    stderr
                });
            }
        });
    });

    if (result.stdout) console.log("CHILD STDOUT:", result.stdout);
    if (result.stderr) console.log("CHILD STDERR:", result.stderr);

    (result.exitCode ?? 1).should.eql(0, `child process should exit cleanly\nSTDOUT: ${result.stdout}\nSTDERR: ${result.stderr}`);
}

describe("CertificateManager process exit behavior", function (this: Mocha.Suite) {
    this.timeout(160_000);

    const testData = beforeTest(this);

    // On WSL over /mnt/c, require() resolution is extremely slow
    // (stat calls on Windows FS from Linux), causing the child to
    // hang during module loading — not a real bug.
    const isWSLCrossMount = process.platform === "linux" && path.resolve(__dirname).startsWith("/mnt/");

    it("undisposed CertificateManager should NOT prevent process exit (native watcher)", async function () {
        if (isWSLCrossMount) {
            this.skip();
            return;
        }
        const loc = path.join(testData.tmpFolder, "EXIT_TEST_NATIVE");
        const script = makeChildScript(loc);
        await runChildAndExpectExit(script, path.resolve(__dirname, ".."), 150_000);
    });

    it("undisposed CertificateManager should NOT prevent process exit (polling watcher)", async function () {
        if (isWSLCrossMount) {
            this.skip();
            return;
        }
        const loc = path.join(testData.tmpFolder, "EXIT_TEST_POLLING");
        const script = makeChildScript(loc, { OPCUA_PKI_USE_POLLING: "true" });
        await runChildAndExpectExit(script, path.resolve(__dirname, ".."), 150_000);
    });
});

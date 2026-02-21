Error.stackTraceLimit = Infinity;

import path from "node:path";
import "should";
import { beforeTest } from "./helpers";

describe("CertificateManager process exit behavior", function (this: Mocha.Suite) {
    this.timeout(15000);

    const testData = beforeTest(this);

    it("undisposed CertificateManager should NOT prevent process exit", async () => {
        const { execFile } = await import("node:child_process");

        const loc = path.join(testData.tmpFolder, "EXIT_TEST");

        // Spawn a child process that creates and initializes a
        // CertificateManager but never disposes it. If the .unref()
        // fix works, the process should exit naturally.
        // If the fix is missing, the process will hang forever.
        const childScript = `
            const { CertificateManager } = require("node-opcua-pki");
            (async () => {
                const cm = new CertificateManager({ location: ${JSON.stringify(loc)} });
                await cm.initialize();
                // Deliberately NOT calling cm.dispose()
                console.log("initialized, waiting for natural exit...");
            })();
        `;

        const exitCode = await new Promise<number | null>((resolve, reject) => {
            const child = execFile(
                process.execPath,
                ["-e", childScript],
                { timeout: 10000, cwd: path.resolve(__dirname, "..") },
                (err, _stdout, _stderr) => {
                    if (err && "killed" in err && err.killed) {
                        // Process was killed by timeout — the fix is not working
                        reject(
                            new Error(
                                "Child process did not exit within 10s — " +
                                    "undisposed CertificateManager is blocking exit. " +
                                    "The .unref() fix on fs.watch handles is likely missing."
                            )
                        );
                    } else {
                        resolve(child.exitCode);
                    }
                }
            );
        });

        (exitCode ?? 1).should.eql(0, "child process should exit cleanly");
    });
});

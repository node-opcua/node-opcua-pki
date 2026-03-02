import fs from "node:fs";
import path from "node:path";
import "should";
import { withLock } from "@ster5/global-mutex";
import { CertificateManager } from "node-opcua-pki";
import should from "should";
import { beforeTest } from "./helpers";

class FastLockCertificateManager extends CertificateManager {
    public compromisedError: Error | undefined;
    public activeOps = 0;
    public completedOps = 0;

    protected override async withLock2<T>(action: () => Promise<T>): Promise<T> {
        return withLock<T>(
            {
                fileToLock: path.join(this.rootDir, "mutex.lock"),
                stale: 500,
                update: 100,
                onCompromised: (err: Error) => {
                    this.compromisedError = err;
                }
            },
            async () => {
                this.activeOps++;
                try {
                    return await action();
                } finally {
                    this.activeOps--;
                    this.completedOps++;
                }
            }
        );
    }

    public runWithLock(action: () => Promise<void>): Promise<void> {
        return this.withLock2(action);
    }
}

describe("dispose() waits for active withLock2() operations", function (this: Mocha.Suite) {
    this.timeout(30_000);

    const testData = beforeTest(this);

    afterEach(async () => {
        await CertificateManager.disposeAll();
    });

    it("should not trigger ECOMPROMISED when PKI folder is deleted after dispose() resolves", async () => {
        const pkiDir = path.join(testData.tmpFolder, "dispose_waits_for_lock");
        const cm = new FastLockCertificateManager({ location: pkiDir });
        await cm.initialize();

        // Start a long-running lock operation (600 ms) without await
        cm.runWithLock(async () => {
            await new Promise<void>((resolve) => setTimeout(resolve, 600));
        });

        // Give the lock time to be acquired.
        await new Promise<void>((resolve) => setTimeout(resolve, 50));

        // dispose() must wait for the lock operation to finish before returning.
        // Once it completes it should be allowed to delete the PKI folder.
        await cm.dispose();

        cm.activeOps.should.eql(0, "all withLock2 operations must have completed before dispose() resolved");
        cm.completedOps.should.be.greaterThanOrEqual(1, "the withLock2 operation must have run to completion");

        await fs.promises.rm(pkiDir, { recursive: true, force: true });

        // Wait long enough for the lock-refresh timer (100 ms interval) to fire
        await new Promise<void>((resolve) => setTimeout(resolve, 300));

        should.not.exist(cm.compromisedError, "ECOMPROMISED must not be triggered when dispose() waits for active locks");
    });
});

import path from "path";
import rimraf from "rimraf";

import { ErrorCallback, g_config, mkdir, warningLog } from "../lib/index";

const tmpFolder = path.join(__dirname, "../tmp");

g_config.silent = !(process.env as any).VERBOSE;

export function grep(data: string, regExp: RegExp): string {
    return data
        .split("\n")
        .filter((l: string) => l.match(regExp))
        .join("\n");
}

let doneOnce = false;

interface TestData {
    tmpFolder: string;
}

export function beforeTest(self: Mocha.Suite, f?: () => Promise<void>): TestData {
    self.timeout("5 minutes");

    const testData: TestData = {
        tmpFolder,
    };

    before(async () => {
        if (process.env.PKITEST === "NOCLEAN") {
            doneOnce = true;
        }
        // tslint:disable-next-line: no-console

        async function __done() {
            if (f) {
                await f();
            }
        }

        testData.tmpFolder = tmpFolder;
        if (!doneOnce) {
            doneOnce = true;
            // tslint:disable-next-line: no-console
            warningLog("    .... cleaning temporary folders ...", tmpFolder);
            await new Promise<void>((resolve, reject) => rimraf(tmpFolder, (err) => (err ? reject(err) : resolve())));
            await mkdir(tmpFolder);
        }
        await __done();
    });
    return testData;
}

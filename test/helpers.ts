import path from "node:path";
import { rimraf } from "rimraf";

import { g_config, mkdirRecursiveSync, warningLog } from "../lib/index";

const tmpFolder = path.join(__dirname, "../tmp");

g_config.silent = !process.env.VERBOSE;

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

export function beforeTest(self: Mocha.Suite, nextFunction?: () => Promise<void>): TestData {
    self.timeout("5 minutes");

    const testData: TestData = {
        tmpFolder
    };

    before(async () => {
        if (process.env.PKITEST === "NOCLEAN") {
            doneOnce = true;
        }
        // tslint:disable-next-line: no-console

        async function next() {
            if (nextFunction) {
                await nextFunction();
            }
        }

        testData.tmpFolder = tmpFolder;
        if (!doneOnce) {
            doneOnce = true;
            // tslint:disable-next-line: no-console
            warningLog("    .... cleaning temporary folders ...", tmpFolder);
            await rimraf(tmpFolder);
            warningLog("    .....  folder cleaned");
            mkdirRecursiveSync(tmpFolder);
            warningLog("    .....  creating empty folder", tmpFolder);
        }
        await next();
    });
    return testData;
}

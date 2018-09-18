import * as del from "del";
import * as path from "path";

import {ErrorCallback, g_config, mkdir} from "../lib";

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

export function beforeTest(self: any, f?: (callback: ErrorCallback) => void): TestData {

    self.timeout("5 minutes");

    const testData: TestData = {
        tmpFolder: ""
    };

    before((done: ErrorCallback) => {

        function __done() {
            doneOnce = true;
            if (f) {
                f(done);
            } else {
                done();
            }
        }

        testData.tmpFolder = tmpFolder;
        if (doneOnce) {
            return __done();
        }
        del(tmpFolder).then(() => {
            mkdir(tmpFolder);
            __done();
        });
    });
    return testData;
}
